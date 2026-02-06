// Package emulated provides an emulated Meshtastic radio that can accept client connections
// and communicate with the mesh network via MQTT.
package emulated

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/generated"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/mqtt"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

const (
	// MinAppVersion is the minimum app version supported by the emulated radio.
	MinAppVersion = 30200
)

// Config is the configuration for the emulated Radio.
type Config struct {
	// MQTTTransport is the MQTT transport to use for mesh communication.
	MQTTTransport *mqtt.Transport

	// NodeID is the ID of the node.
	NodeID core.NodeID
	// LongName is the long name of the node.
	LongName string
	// ShortName is the short name of the node.
	ShortName string
	// Channels is the set of channels the radio will listen and transmit on.
	Channels *pb.ChannelSet

	// BroadcastNodeInfoInterval is the interval at which the radio will broadcast a NodeInfo.
	// The zero value disables broadcasting NodeInfo.
	BroadcastNodeInfoInterval time.Duration
	// BroadcastPositionInterval is the interval at which the radio will broadcast Position.
	// The zero value disables broadcasting Position.
	BroadcastPositionInterval time.Duration

	// Position coordinates
	PositionLatitudeI  int32
	PositionLongitudeI int32
	PositionAltitude   int32

	// TCPListenAddr is the address the emulated radio will listen on for TCP connections.
	TCPListenAddr string

	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

func (c *Config) validate() error {
	if c.MQTTTransport == nil {
		return fmt.Errorf("MQTTTransport is required")
	}
	if c.NodeID == 0 {
		return fmt.Errorf("NodeID is required")
	}
	if c.LongName == "" {
		c.LongName = c.NodeID.DefaultLongName()
	}
	if c.ShortName == "" {
		c.ShortName = c.NodeID.DefaultShortName()
	}
	if c.Channels == nil {
		return fmt.Errorf("Channels is required")
	}
	if len(c.Channels.Settings) == 0 {
		return fmt.Errorf("Channels.Settings should be non-empty")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// Radio emulates a Meshtastic Node, communicating with a meshtastic network via MQTT.
type Radio struct {
	cfg    Config
	mqtt   *mqtt.Transport
	log    *slog.Logger

	mu                   sync.Mutex
	fromRadioSubscribers map[chan<- *pb.FromRadio]struct{}
	nodeDB               map[uint32]*pb.NodeInfo
	packetID             uint32
}

// NewRadio creates a new emulated radio.
func NewRadio(cfg Config) (*Radio, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return &Radio{
		cfg:                  cfg,
		log:                  cfg.Logger.WithGroup("radio").With("node", cfg.NodeID.String()),
		fromRadioSubscribers: map[chan<- *pb.FromRadio]struct{}{},
		mqtt:                 cfg.MQTTTransport,
		nodeDB:               map[uint32]*pb.NodeInfo{},
	}, nil
}

// Run starts the radio. It blocks until the context is cancelled.
func (r *Radio) Run(ctx context.Context) error {
	// Set up MQTT packet handler
	r.mqtt.SetPacketHandler(r.handleMQTTPacket)

	// Subscribe to all configured channels
	for _, ch := range r.cfg.Channels.Settings {
		r.log.Debug("subscribing to channel", "channel", ch.Name)
		r.mqtt.AddChannel(ch.Name)
	}

	if err := r.mqtt.Start(ctx); err != nil {
		return fmt.Errorf("starting MQTT transport: %w", err)
	}

	eg, egCtx := errgroup.WithContext(ctx)

	// Broadcast NodeInfo periodically
	if r.cfg.BroadcastNodeInfoInterval > 0 {
		eg.Go(func() error {
			ticker := time.NewTicker(r.cfg.BroadcastNodeInfoInterval)
			defer ticker.Stop()
			for {
				if err := r.broadcastNodeInfo(egCtx); err != nil {
					r.log.Error("failed to broadcast node info", "error", err)
				}
				select {
				case <-egCtx.Done():
					return nil
				case <-ticker.C:
				}
			}
		})
	}

	// Broadcast Position periodically
	if r.cfg.BroadcastPositionInterval > 0 {
		eg.Go(func() error {
			ticker := time.NewTicker(r.cfg.BroadcastPositionInterval)
			defer ticker.Stop()
			for {
				if err := r.broadcastPosition(egCtx); err != nil {
					r.log.Error("failed to broadcast position", "error", err)
				}
				select {
				case <-egCtx.Done():
					return nil
				case <-ticker.C:
				}
			}
		})
	}

	// TCP server
	if r.cfg.TCPListenAddr != "" {
		eg.Go(func() error {
			return r.listenTCP(egCtx)
		})
	}

	return eg.Wait()
}

func (r *Radio) handleMQTTPacket(pkt transport.NetworkPacket) {
	// Dispatch to FromRadio subscribers
	if err := r.dispatchMessageToFromRadio(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Packet{
			Packet: pkt.Packet,
		},
	}); err != nil {
		r.log.Error("failed to dispatch message", "error", err)
	}

	// Only process primary channel messages for node DB updates
	if len(r.cfg.Channels.Settings) == 0 {
		return
	}
	primaryName := r.cfg.Channels.Settings[0].Name
	primaryPSK := r.cfg.Channels.Settings[0].Psk
	if pkt.Channel != primaryName {
		return
	}

	// Decrypt if needed
	var data *pb.Data
	switch payload := pkt.Packet.PayloadVariant.(type) {
	case *pb.MeshPacket_Decoded:
		data = payload.Decoded
	case *pb.MeshPacket_Encrypted:
		plaintext, err := crypto.XOR(payload.Encrypted, primaryPSK, pkt.Packet.Id, pkt.Packet.From)
		if err != nil {
			r.log.Debug("decryption failed", "error", err)
			return
		}
		data = &pb.Data{}
		if err := proto.Unmarshal(plaintext, data); err != nil {
			r.log.Debug("unmarshal failed", "error", err)
			return
		}
	default:
		return
	}

	// Update node DB based on message type
	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			return
		}
		r.updateNodeDB(pkt.Packet.From, func(nodeInfo *pb.NodeInfo) {
			nodeInfo.User = user
		})
	case pb.PortNum_POSITION_APP:
		position := &pb.Position{}
		if err := proto.Unmarshal(data.Payload, position); err != nil {
			return
		}
		r.updateNodeDB(pkt.Packet.From, func(nodeInfo *pb.NodeInfo) {
			nodeInfo.Position = position
		})
	case pb.PortNum_TELEMETRY_APP:
		telemetry := &pb.Telemetry{}
		if err := proto.Unmarshal(data.Payload, telemetry); err != nil {
			return
		}
		if metrics := telemetry.GetDeviceMetrics(); metrics != nil {
			r.updateNodeDB(pkt.Packet.From, func(nodeInfo *pb.NodeInfo) {
				nodeInfo.DeviceMetrics = metrics
			})
		}
	}
}

func (r *Radio) updateNodeDB(nodeID uint32, updateFunc func(*pb.NodeInfo)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodeInfo, ok := r.nodeDB[nodeID]
	if !ok {
		nodeInfo = &pb.NodeInfo{Num: nodeID}
	}
	updateFunc(nodeInfo)
	nodeInfo.LastHeard = uint32(time.Now().Unix())
	r.nodeDB[nodeID] = nodeInfo
}

func (r *Radio) getNodeDB() []*pb.NodeInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodes := make([]*pb.NodeInfo, 0, len(r.nodeDB))
	for _, node := range r.nodeDB {
		nodes = append(nodes, proto.Clone(node).(*pb.NodeInfo))
	}
	return nodes
}

func (r *Radio) nextPacketID() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packetID++
	return r.packetID
}

func (r *Radio) sendPacket(_ context.Context, packet *pb.MeshPacket) error {
	packet.Id = r.nextPacketID()
	channelName := r.cfg.Channels.Settings[0].Name
	return r.mqtt.SendPacket(channelName, packet)
}

func (r *Radio) broadcastNodeInfo(ctx context.Context) error {
	r.log.Debug("broadcasting NodeInfo")
	user := &pb.User{
		Id:        r.cfg.NodeID.String(),
		LongName:  r.cfg.LongName,
		ShortName: r.cfg.ShortName,
		HwModel:   pb.HardwareModel_PRIVATE_HW,
	}
	userBytes, err := proto.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshalling user: %w", err)
	}
	return r.sendPacket(ctx, &pb.MeshPacket{
		From: r.cfg.NodeID.Uint32(),
		To:   core.BroadcastNodeID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_NODEINFO_APP,
				Payload: userBytes,
			},
		},
	})
}

func (r *Radio) broadcastPosition(ctx context.Context) error {
	r.log.Debug("broadcasting Position")
	position := &pb.Position{
		LatitudeI:  &r.cfg.PositionLatitudeI,
		LongitudeI: &r.cfg.PositionLongitudeI,
		Altitude:   &r.cfg.PositionAltitude,
		Time:       uint32(time.Now().Unix()),
	}
	positionBytes, err := proto.Marshal(position)
	if err != nil {
		return fmt.Errorf("marshalling position: %w", err)
	}
	return r.sendPacket(ctx, &pb.MeshPacket{
		From: r.cfg.NodeID.Uint32(),
		To:   core.BroadcastNodeID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_POSITION_APP,
				Payload: positionBytes,
			},
		},
	})
}

func (r *Radio) dispatchMessageToFromRadio(msg *pb.FromRadio) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ch := range r.fromRadioSubscribers {
		select {
		case ch <- msg:
		default:
			// Skip if channel is full
		}
	}
	return nil
}

func (r *Radio) handleToRadioWantConfigID(conn *stream.Conn, req *pb.ToRadio_WantConfigId) error {
	// Send MyInfo
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_MyInfo{
			MyInfo: &pb.MyNodeInfo{
				MyNodeNum:     r.cfg.NodeID.Uint32(),
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
				FirmwareVersion:    "2.2.19-emulated",
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

	// Send own node info
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_NodeInfo{
			NodeInfo: &pb.NodeInfo{
				Num: r.cfg.NodeID.Uint32(),
				User: &pb.User{
					Id:        r.cfg.NodeID.String(),
					LongName:  r.cfg.LongName,
					ShortName: r.cfg.ShortName,
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("writing own NodeInfo: %w", err)
	}

	// Send all known nodes
	for _, nodeInfo := range r.getNodeDB() {
		if err := conn.Write(&pb.FromRadio{
			PayloadVariant: &pb.FromRadio_NodeInfo{
				NodeInfo: nodeInfo,
			},
		}); err != nil {
			return fmt.Errorf("writing NodeInfo: %w", err)
		}
	}

	// Send primary channel
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Channel{
			Channel: &pb.Channel{
				Index:    0,
				Settings: &pb.ChannelSettings{},
				Role:     pb.Channel_PRIMARY,
			},
		},
	}); err != nil {
		return fmt.Errorf("writing Channel: %w", err)
	}

	// Send device config
	if err := conn.Write(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Config{
			Config: &pb.Config{
				PayloadVariant: &pb.Config_Device{
					Device: &pb.Config_DeviceConfig{
						SerialEnabled:         true,
						NodeInfoBroadcastSecs: uint32(r.cfg.BroadcastNodeInfoInterval.Seconds()),
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
			ConfigCompleteId: req.WantConfigId,
		},
	}); err != nil {
		return fmt.Errorf("writing ConfigComplete: %w", err)
	}

	return nil
}

func (r *Radio) handleConn(ctx context.Context, underlying io.ReadWriteCloser) error {
	streamConn := stream.NewRadioConn(underlying)
	defer streamConn.Close()

	eg, egCtx := errgroup.WithContext(ctx)

	// Handle incoming messages from client
	eg.Go(func() error {
		for {
			select {
			case <-egCtx.Done():
				return nil
			default:
			}
			msg := &pb.ToRadio{}
			if err := streamConn.Read(msg); err != nil {
				return fmt.Errorf("reading from stream: %w", err)
			}
			r.log.Debug("received ToRadio", "msg", msg)

			switch payload := msg.PayloadVariant.(type) {
			case *pb.ToRadio_Disconnect:
				return nil
			case *pb.ToRadio_WantConfigId:
				if err := r.handleToRadioWantConfigID(streamConn, payload); err != nil {
					return fmt.Errorf("handling WantConfigId: %w", err)
				}
			case *pb.ToRadio_Packet:
				// Handle admin requests
				if decoded := payload.Packet.GetDecoded(); decoded != nil {
					if decoded.Portnum == pb.PortNum_ADMIN_APP {
						if err := r.handleAdminMessage(streamConn, payload.Packet, decoded); err != nil {
							return err
						}
					}
				}
			}
		}
	})

	// Handle sending messages to client
	eg.Go(func() error {
		ch := make(chan *pb.FromRadio, 16)
		r.mu.Lock()
		r.fromRadioSubscribers[ch] = struct{}{}
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			delete(r.fromRadioSubscribers, ch)
			r.mu.Unlock()
		}()

		for {
			select {
			case <-egCtx.Done():
				return nil
			case msg := <-ch:
				if err := streamConn.Write(msg); err != nil {
					return fmt.Errorf("writing to stream: %w", err)
				}
			}
		}
	})

	return eg.Wait()
}

func (r *Radio) handleAdminMessage(conn *stream.Conn, packet *pb.MeshPacket, decoded *pb.Data) error {
	admin := &pb.AdminMessage{}
	if err := proto.Unmarshal(decoded.Payload, admin); err != nil {
		return fmt.Errorf("unmarshalling admin: %w", err)
	}

	switch admin.PayloadVariant.(type) {
	case *pb.AdminMessage_GetChannelRequest:
		resp := &pb.AdminMessage{
			PayloadVariant: &pb.AdminMessage_GetChannelResponse{
				GetChannelResponse: &pb.Channel{
					Index:    0,
					Settings: &pb.ChannelSettings{},
					Role:     pb.Channel_DISABLED,
				},
			},
		}
		respBytes, err := proto.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshalling response: %w", err)
		}
		return conn.Write(&pb.FromRadio{
			PayloadVariant: &pb.FromRadio_Packet{
				Packet: &pb.MeshPacket{
					Id:   r.nextPacketID(),
					From: r.cfg.NodeID.Uint32(),
					To:   r.cfg.NodeID.Uint32(),
					PayloadVariant: &pb.MeshPacket_Decoded{
						Decoded: &pb.Data{
							Portnum:   pb.PortNum_ADMIN_APP,
							Payload:   respBytes,
							RequestId: packet.Id,
						},
					},
				},
			},
		})
	}
	return nil
}

func (r *Radio) listenTCP(ctx context.Context) error {
	l, err := net.Listen("tcp", r.cfg.TCPListenAddr)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	r.log.Info("listening for TCP connections", "addr", r.cfg.TCPListenAddr)

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // Context cancelled
			}
			r.log.Error("failed to accept connection", "error", err)
			continue
		}
		go func() {
			if err := r.handleConn(ctx, c); err != nil {
				r.log.Error("failed to handle TCP connection", "error", err)
			}
		}()
	}
}

// Conn returns an in-memory connection to the emulated radio.
func (r *Radio) Conn(ctx context.Context) net.Conn {
	clientConn, radioConn := net.Pipe()
	go func() {
		if err := r.handleConn(ctx, radioConn); err != nil {
			r.log.Error("failed to handle in-memory connection", "error", err)
		}
	}()
	return clientConn
}
