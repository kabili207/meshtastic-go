// Package clientapi implements the Meshtastic client API server. It handles
// the device handshake protocol (WantConfigId → ConfigCompleteId), manages
// connected client subscriptions, and serves both TCP and in-memory connections.
package clientapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/lora"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"golang.org/x/sync/errgroup"
)

const (
	// MinAppVersion is the minimum app version reported to clients.
	MinAppVersion = 30200
	// FirmwareVersion is the firmware version string reported to clients.
	FirmwareVersion = "2.2.19-emulated"
	// subscriberBufferSize is the channel buffer for FromRadio subscribers.
	subscriberBufferSize = 16
)

// NodeInfoProvider supplies node information for the client handshake.
type NodeInfoProvider interface {
	// SelfInfo returns the self node's NodeInfo.
	SelfInfo() *pb.NodeInfo
	// All returns all tracked nodes (cloned).
	All() []*pb.NodeInfo
	// Channel returns the channel a node was last heard on, if recorded. The
	// handshake turns it into the NodeInfo.Channel index a phone expects, against
	// the channel table it sends.
	Channel(nodeID uint32) (core.ChannelDef, bool)
}

// PacketIDFunc returns the next packet ID for outgoing packets.
type PacketIDFunc func() uint32

// OutboundPacketHandler is called when a client sends a mesh packet
// via ToRadio that should be forwarded to the mesh.
type OutboundPacketHandler func(ctx context.Context, packet *pb.MeshPacket)

// Config configures a client API Server.
type Config struct {
	// NodeID is this node's identity.
	NodeID core.NodeID
	// LongName for the handshake metadata.
	LongName string
	// ShortName for the handshake metadata.
	ShortName string

	// Channels is the channel configuration to report during handshake.
	Channels *pb.ChannelSet

	// NodeInfoBroadcastSecs is reported in the device config during handshake.
	NodeInfoBroadcastSecs uint32

	// Nodes provides node information for the handshake.
	Nodes NodeInfoProvider

	// NextPacketID returns the next packet ID for admin responses.
	NextPacketID PacketIDFunc

	// OnOutboundPacket is called when a client sends a packet to the mesh.
	OnOutboundPacket OutboundPacketHandler

	// TCPListenAddr is the address to listen on for TCP connections.
	// If empty, no TCP listener is started.
	TCPListenAddr string

	// Logger for client API events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Server manages client connections and implements the Meshtastic client API.
type Server struct {
	cfg Config
	log *slog.Logger

	mu          sync.Mutex
	subscribers map[chan<- *pb.FromRadio]struct{}
}

// New creates a client API Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:         cfg,
		log:         cfg.Logger.WithGroup("clientapi"),
		subscribers: make(map[chan<- *pb.FromRadio]struct{}),
	}
}

// Start begins the TCP listener if configured. It blocks until the context
// is cancelled.
func (s *Server) Start(ctx context.Context) {
	if s.cfg.TCPListenAddr == "" {
		<-ctx.Done()
		return
	}
	s.listenTCP(ctx)
}

// DispatchToClients sends a FromRadio message to all connected clients.
// Non-blocking: drops the message for clients whose buffers are full.
func (s *Server) DispatchToClients(msg *pb.FromRadio) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- msg:
		default:
			// Skip if channel is full
		}
	}
}

// Conn returns an in-memory connection to the server, suitable for
// creating a client.ClientTransport. The returned net.Conn is the
// client side of the pipe.
func (s *Server) Conn(ctx context.Context) net.Conn {
	clientConn, radioConn := net.Pipe()
	go func() {
		if err := s.handleConn(ctx, radioConn); err != nil {
			s.log.Error("failed to handle in-memory connection", "error", err)
		}
	}()
	return clientConn
}

// channelIndexFor maps the channel a node was last heard on to its index in the
// table the handshake sends. Zero, the primary, when nothing is recorded or the
// channel is not in the configured table (a runtime-added channel, for instance).
func (s *Server) channelIndexFor(nodeID uint32) uint32 {
	ch, ok := s.cfg.Nodes.Channel(nodeID)
	if !ok {
		return 0
	}
	for i, settings := range s.cfg.Channels.Settings {
		if i >= core.MaxChannels {
			break
		}
		if core.SameChannel(core.ChannelFromSettings(settings), ch) {
			return uint32(i)
		}
	}
	return 0
}

func (s *Server) addSubscriber(ch chan<- *pb.FromRadio) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers[ch] = struct{}{}
}

func (s *Server) removeSubscriber(ch chan<- *pb.FromRadio) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subscribers, ch)
}

func (s *Server) handleConn(ctx context.Context, rwc io.ReadWriteCloser) error {
	conn := stream.NewRadioConn(rwc)
	defer conn.Close()

	eg, egCtx := errgroup.WithContext(ctx)

	// Read ToRadio messages from the client
	eg.Go(func() error {
		for {
			select {
			case <-egCtx.Done():
				return nil
			default:
			}
			msg := &pb.ToRadio{}
			if err := conn.Read(msg); err != nil {
				return fmt.Errorf("reading from stream: %w", err)
			}
			s.log.Debug("received ToRadio", "msg", msg)

			switch payload := msg.PayloadVariant.(type) {
			case *pb.ToRadio_Disconnect:
				return nil
			case *pb.ToRadio_WantConfigId:
				if err := s.handleHandshake(conn, payload.WantConfigId); err != nil {
					return fmt.Errorf("handling WantConfigId: %w", err)
				}
			case *pb.ToRadio_Packet:
				if decoded := payload.Packet.GetDecoded(); decoded != nil {
					if decoded.Portnum == pb.PortNum_ADMIN_APP {
						if err := s.handleAdminMessage(conn, payload.Packet, decoded); err != nil {
							return err
						}
						continue
					}
				}
				// Forward non-admin packets to the mesh
				if s.cfg.OnOutboundPacket != nil {
					s.cfg.OnOutboundPacket(egCtx, payload.Packet)
				}
			}
		}
	})

	// Write FromRadio messages to the client
	eg.Go(func() error {
		ch := make(chan *pb.FromRadio, subscriberBufferSize)
		s.addSubscriber(ch)
		defer s.removeSubscriber(ch)

		for {
			select {
			case <-egCtx.Done():
				return nil
			case msg := <-ch:
				if err := conn.Write(msg); err != nil {
					return fmt.Errorf("writing to stream: %w", err)
				}
			}
		}
	})

	return eg.Wait()
}

func (s *Server) handleHandshake(conn *stream.Conn, configID uint32) error {
	// Send MyInfo
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_MyInfo{
			MyInfo: &pb.MyNodeInfo{
				MyNodeNum:     s.cfg.NodeID.Uint32(),
				RebootCount:   0,
				MinAppVersion: MinAppVersion,
			},
		},
	}); err != nil {
		return fmt.Errorf("writing MyInfo: %w", err)
	}

	// Send Metadata
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Metadata{
			Metadata: &pb.DeviceMetadata{
				FirmwareVersion:    FirmwareVersion,
				DeviceStateVersion: 22,
				CanShutdown:        true,
				HasWifi:            true,
				HasBluetooth:       true,
				HwModel:            pb.HardwareModel_PRIVATE_HW,
			},
		},
	}); err != nil {
		return fmt.Errorf("writing Metadata: %w", err)
	}

	// Send the region-to-preset map, right after metadata and before the first
	// channel, where firmware 2.8 sends it. Clients use it to refuse an illegal
	// region and preset pairing.
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_RegionPresets{
			RegionPresets: lora.RegionPresetMap(),
		},
	}); err != nil {
		return fmt.Errorf("writing RegionPresets: %w", err)
	}

	// Send self node info
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_NodeInfo{
			NodeInfo: s.cfg.Nodes.SelfInfo(),
		},
	}); err != nil {
		return fmt.Errorf("writing own NodeInfo: %w", err)
	}

	// Send all known nodes. Each carries the index, into the table sent below, of
	// the channel it was last heard on, which is how a phone picks a DM channel.
	for _, nodeInfo := range s.cfg.Nodes.All() {
		nodeInfo.Channel = s.channelIndexFor(nodeInfo.Num)
		if err := conn.Write(&pb.FromRadio{
			PayloadVariant: &pb.FromRadio_NodeInfo{
				NodeInfo: nodeInfo,
			},
		}); err != nil {
			return fmt.Errorf("writing NodeInfo: %w", err)
		}
	}

	// Send the channel table. A phone expects every slot, so unconfigured ones go
	// out disabled, the way a device reports them.
	for i := 0; i < core.MaxChannels; i++ {
		ch := &pb.Channel{Index: int32(i), Role: pb.Channel_DISABLED, Settings: &pb.ChannelSettings{}}
		if i < len(s.cfg.Channels.Settings) {
			ch.Settings = s.cfg.Channels.Settings[i]
			ch.Role = pb.Channel_SECONDARY
			if i == 0 {
				ch.Role = pb.Channel_PRIMARY
			}
		}
		if err := conn.Write(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Channel{Channel: ch}}); err != nil {
			return fmt.Errorf("writing Channel: %w", err)
		}
	}

	// Send device config
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Config{
			Config: &pb.Config{
				PayloadVariant: &pb.Config_Device{
					Device: &pb.Config_DeviceConfig{
						SerialEnabled:         true,
						NodeInfoBroadcastSecs: s.cfg.NodeInfoBroadcastSecs,
					},
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("writing Config: %w", err)
	}

	// Send ConfigComplete
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_ConfigCompleteId{
			ConfigCompleteId: configID,
		},
	}); err != nil {
		return fmt.Errorf("writing ConfigComplete: %w", err)
	}

	return nil
}

func (s *Server) listenTCP(ctx context.Context) {
	l, err := net.Listen("tcp", s.cfg.TCPListenAddr)
	if err != nil {
		s.log.Error("failed to listen", "addr", s.cfg.TCPListenAddr, "error", err)
		return
	}
	s.log.Info("listening for TCP connections", "addr", s.cfg.TCPListenAddr)

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // Context cancelled
			}
			s.log.Error("failed to accept connection", "error", err)
			continue
		}
		go func() {
			if err := s.handleConn(ctx, c); err != nil {
				s.log.Error("failed to handle TCP connection", "error", err)
			}
		}()
	}
}
