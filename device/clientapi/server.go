// Package clientapi implements the Meshtastic client API server. It handles
// the device handshake protocol (WantConfigId → ConfigCompleteId), manages
// connected client subscriptions, and serves both TCP and in-memory connections.
package clientapi

import (
	"context"
	"errors"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	// MinAppVersion is the minimum app version reported to clients.
	MinAppVersion = 30200
	// FirmwareVersion is the firmware release this library tracks, reported to
	// clients. Apps gate features on it, so it moves with the firmware we follow.
	FirmwareVersion = "2.8.2.go"
	// deviceStateVersion is firmware's DEVICESTATE_CUR_VER for that release.
	deviceStateVersion = 25
	// subscriberBufferSize is the channel buffer for FromRadio subscribers.
	subscriberBufferSize = 16

	// Firmware's special want_config nonces: config without the node database,
	// and the node database without config.
	nonceOnlyConfig = 69420
	nonceOnlyNodes  = 69421
)

// excludedModules hides every module settings page from the app. A Go node runs
// none of those modules, and has no Bluetooth or WiFi radio to configure.
const excludedModules = uint32(pb.ExcludedModules_MQTT_CONFIG | pb.ExcludedModules_SERIAL_CONFIG |
	pb.ExcludedModules_EXTNOTIF_CONFIG | pb.ExcludedModules_STOREFORWARD_CONFIG | pb.ExcludedModules_RANGETEST_CONFIG |
	pb.ExcludedModules_TELEMETRY_CONFIG | pb.ExcludedModules_CANNEDMSG_CONFIG | pb.ExcludedModules_AUDIO_CONFIG |
	pb.ExcludedModules_REMOTEHARDWARE_CONFIG | pb.ExcludedModules_NEIGHBORINFO_CONFIG |
	pb.ExcludedModules_AMBIENTLIGHTING_CONFIG | pb.ExcludedModules_DETECTIONSENSOR_CONFIG |
	pb.ExcludedModules_PAXCOUNTER_CONFIG | pb.ExcludedModules_BLUETOOTH_CONFIG | pb.ExcludedModules_NETWORK_CONFIG |
	pb.ExcludedModules_STATUSMESSAGE_CONFIG | pb.ExcludedModules_TRAFFICMANAGEMENT_CONFIG |
	pb.ExcludedModules_TAK_CONFIG | pb.ExcludedModules_MESHBEACON_CONFIG)

// errDisconnect ends a connection the client asked to close.
var errDisconnect = errors.New("client disconnected")

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
	// HwModel is the hardware model reported in the metadata and own NodeInfo.
	HwModel pb.HardwareModel
	// PublicKey is this node's X25519 public key, reported in the security
	// config and own NodeInfo. The private key is never sent to clients.
	PublicKey []byte

	// Channels is the channel configuration to report during handshake.
	Channels *pb.ChannelSet
	// LoRa is the LoRa config reported to clients. Without a region, apps
	// prompt the user to pick one.
	LoRa *pb.Config_LoRaConfig

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

	mu      sync.Mutex
	clients map[*client]struct{}

	// The settings clients see. Firmware keeps these as LocalConfig and
	// LocalModuleConfig; so do we, so each section maps onto the Config and
	// ModuleConfig oneofs by name.
	settingsMu   sync.RWMutex
	localConfig  *pb.LocalConfig
	moduleConfig *pb.LocalModuleConfig
}

// client is one connected app.
type client struct {
	conn *stream.Conn
	// out carries live packets, held back until ready closes after the first
	// handshake, as firmware only sends packets once in STATE_SEND_PACKETS.
	out       chan *pb.FromRadio
	ready     chan struct{}
	readyOnce sync.Once
}

// New creates a client API Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	lora := &pb.Config_LoRaConfig{}
	if cfg.LoRa != nil {
		lora = proto.Clone(cfg.LoRa).(*pb.Config_LoRaConfig)
	}
	return &Server{
		cfg:     cfg,
		log:     cfg.Logger.WithGroup("clientapi"),
		clients: make(map[*client]struct{}),
		localConfig: &pb.LocalConfig{
			Device: &pb.Config_DeviceConfig{
				SerialEnabled:         true,
				NodeInfoBroadcastSecs: cfg.NodeInfoBroadcastSecs,
			},
			Lora:     lora,
			Security: &pb.Config_SecurityConfig{PublicKey: cfg.PublicKey},
		},
		moduleConfig: &pb.LocalModuleConfig{},
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
	for c := range s.clients {
		select {
		case c.out <- msg:
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
	for i, def := range core.ChannelsFromSet(s.cfg.Channels) {
		if i >= core.MaxChannels {
			break
		}
		if def != nil && core.SameChannel(def, ch) {
			return uint32(i)
		}
	}
	return 0
}

func (s *Server) addClient(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c] = struct{}{}
}

func (s *Server) removeClient(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, c)
}

func (s *Server) handleConn(ctx context.Context, rwc io.ReadWriteCloser) error {
	c := &client{
		conn:  stream.NewRadioConn(rwc),
		out:   make(chan *pb.FromRadio, subscriberBufferSize),
		ready: make(chan struct{}),
	}
	defer c.conn.Close()
	s.addClient(c)
	defer s.removeClient(c)

	eg, egCtx := errgroup.WithContext(ctx)
	// Closing the stream unblocks the reader when the writer or context ends.
	go func() {
		<-egCtx.Done()
		c.conn.Close()
	}()

	eg.Go(func() error { return s.readLoop(egCtx, c) })
	eg.Go(func() error {
		select {
		case <-egCtx.Done():
			return nil
		case <-c.ready:
		}
		for {
			select {
			case <-egCtx.Done():
				return nil
			case msg := <-c.out:
				if err := c.conn.Write(msg); err != nil {
					return fmt.Errorf("writing to stream: %w", err)
				}
			}
		}
	})

	if err := eg.Wait(); err != nil && !errors.Is(err, errDisconnect) && egCtx.Err() == nil {
		return err
	}
	return nil
}

func (s *Server) readLoop(ctx context.Context, c *client) error {
	for {
		msg := &pb.ToRadio{}
		if err := c.conn.Read(msg); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading from stream: %w", err)
		}
		s.log.Debug("received ToRadio", "msg", msg)

		switch payload := msg.PayloadVariant.(type) {
		case *pb.ToRadio_Disconnect:
			return errDisconnect
		case *pb.ToRadio_Heartbeat:
			if err := c.conn.Write(s.queueStatus(0)); err != nil {
				return fmt.Errorf("writing QueueStatus: %w", err)
			}
		case *pb.ToRadio_WantConfigId:
			if err := s.handleHandshake(c.conn, payload.WantConfigId); err != nil {
				return fmt.Errorf("handling WantConfigId: %w", err)
			}
			c.readyOnce.Do(func() { close(c.ready) })
		case *pb.ToRadio_Packet:
			if decoded := payload.Packet.GetDecoded(); decoded != nil {
				if decoded.Portnum == pb.PortNum_ADMIN_APP {
					if err := s.handleAdminMessage(c.conn, payload.Packet, decoded); err != nil {
						return err
					}
					continue
				}
			}
			// Forward non-admin packets to the mesh
			if s.cfg.OnOutboundPacket != nil {
				s.cfg.OnOutboundPacket(ctx, payload.Packet)
			}
		}
	}
}

// queueStatus reports a send queue that is never full: packets go straight to
// the transport.
func (s *Server) queueStatus(packetID uint32) *pb.FromRadio {
	return &pb.FromRadio{PayloadVariant: &pb.FromRadio_QueueStatus{QueueStatus: &pb.QueueStatus{
		Free:         subscriberBufferSize,
		Maxlen:       subscriberBufferSize,
		MeshPacketId: packetID,
	}}}
}

// handleHandshake sends the config in the order firmware's PhoneAPI does, which
// client apps assume: my info, UI config, own node, metadata, region presets,
// channels, config, module config, other nodes, file manifest, complete.
func (s *Server) handleHandshake(conn *stream.Conn, nonce uint32) error {
	all := s.cfg.Nodes.All()
	frames := []*pb.FromRadio{
		{PayloadVariant: &pb.FromRadio_MyInfo{MyInfo: &pb.MyNodeInfo{
			MyNodeNum:     s.cfg.NodeID.Uint32(),
			MinAppVersion: MinAppVersion,
			PioEnv:        "meshtastic-go",
			NodedbCount:   uint32(len(all) + 1),
		}}},
		{PayloadVariant: &pb.FromRadio_DeviceuiConfig{DeviceuiConfig: &pb.DeviceUIConfig{}}},
		{PayloadVariant: &pb.FromRadio_NodeInfo{NodeInfo: s.ownNodeInfo()}},
	}

	if nonce != nonceOnlyNodes {
		frames = append(frames,
			&pb.FromRadio{PayloadVariant: &pb.FromRadio_Metadata{Metadata: s.metadata()}},
			// Clients use the preset map to refuse an illegal region and preset pairing.
			&pb.FromRadio{PayloadVariant: &pb.FromRadio_RegionPresets{RegionPresets: lora.RegionPresetMap()}},
		)
		frames = append(frames, s.channelFrames()...)
		frames = append(frames, s.configFrames()...)
	}

	if nonce != nonceOnlyConfig {
		// Each node carries the index, into the channel table, of the channel it
		// was last heard on, which is how a phone picks a DM channel.
		for _, info := range all {
			info.Channel = s.channelIndexFor(info.Num)
			if info.User != nil {
				info.User.Id = core.NodeID(info.Num).String()
			}
			frames = append(frames, &pb.FromRadio{PayloadVariant: &pb.FromRadio_NodeInfo{NodeInfo: info}})
		}
	}

	frames = append(frames, &pb.FromRadio{PayloadVariant: &pb.FromRadio_ConfigCompleteId{ConfigCompleteId: nonce}})
	for _, f := range frames {
		if err := conn.Write(f); err != nil {
			return fmt.Errorf("writing %T: %w", f.PayloadVariant, err)
		}
	}
	return nil
}

// ownNodeInfo is the self node as firmware presents it to the phone: marked a
// favorite, with the identity details apps display.
func (s *Server) ownNodeInfo() *pb.NodeInfo {
	info := s.cfg.Nodes.SelfInfo()
	info.IsFavorite = true
	if info.User != nil {
		info.User.HwModel = s.cfg.HwModel
		info.User.PublicKey = s.cfg.PublicKey
		s.settingsMu.RLock()
		info.User.Role = s.localConfig.GetDevice().GetRole()
		s.settingsMu.RUnlock()
	}
	return info
}

func (s *Server) metadata() *pb.DeviceMetadata {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	return &pb.DeviceMetadata{
		FirmwareVersion:    FirmwareVersion,
		DeviceStateVersion: deviceStateVersion,
		Role:               s.localConfig.GetDevice().GetRole(),
		PositionFlags:      s.localConfig.GetPosition().GetPositionFlags(),
		HwModel:            s.cfg.HwModel,
		HasPKC:             len(s.cfg.PublicKey) == 32,
		ExcludedModules:    excludedModules,
	}
}

// channelFrames sends every channel slot, unconfigured ones disabled, the way a
// device reports them.
func (s *Server) channelFrames() []*pb.FromRadio {
	frames := make([]*pb.FromRadio, core.MaxChannels)
	for i := range frames {
		ch := &pb.Channel{Index: int32(i), Role: pb.Channel_DISABLED, Settings: &pb.ChannelSettings{}}
		if i < len(s.cfg.Channels.Settings) {
			ch.Settings = s.cfg.Channels.Settings[i]
			ch.Role = pb.Channel_SECONDARY
			if i == 0 {
				ch.Role = pb.Channel_PRIMARY
			}
		}
		frames[i] = &pb.FromRadio{PayloadVariant: &pb.FromRadio_Channel{Channel: ch}}
	}
	return frames
}

// configFrames sends one Config per section and one ModuleConfig per module,
// in field order, empty where nothing is set, as firmware does.
func (s *Server) configFrames() []*pb.FromRadio {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	var frames []*pb.FromRadio
	for _, c := range sections(&pb.Config{}, s.localConfig) {
		frames = append(frames, &pb.FromRadio{PayloadVariant: &pb.FromRadio_Config{Config: c.(*pb.Config)}})
	}
	for _, m := range sections(&pb.ModuleConfig{}, s.moduleConfig) {
		frames = append(frames, &pb.FromRadio{PayloadVariant: &pb.FromRadio_ModuleConfig{ModuleConfig: m.(*pb.ModuleConfig)}})
	}
	return frames
}

// sections builds one wrapper per payload_variant field, in field order, each
// holding a copy of local's field of the same name, or an empty section.
func sections(wrapper proto.Message, local proto.Message) []proto.Message {
	wd := wrapper.ProtoReflect().Descriptor()
	fields := wd.Oneofs().ByName("payload_variant").Fields()
	out := make([]proto.Message, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		w := wrapper.ProtoReflect().New()
		val := w.NewField(fd)
		lm := local.ProtoReflect()
		if lfd := lm.Descriptor().Fields().ByName(fd.Name()); lfd != nil && lm.Has(lfd) {
			val = protoreflect.ValueOfMessage(proto.Clone(lm.Get(lfd).Message().Interface()).ProtoReflect())
		}
		w.Set(fd, val)
		out = append(out, w.Interface())
	}
	return out
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
