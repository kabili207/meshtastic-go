// Package node provides the glue that wires together the device components
// (nodedb, broadcast, clientapi) over a raw transport to form a complete
// emulated Meshtastic node.
package node

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/dedupe"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/broadcast"
	"github.com/kabili207/meshtastic-go/device/clientapi"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/device/nodedb"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/raw"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

// Config configures a Node.
type Config struct {
	// Transport is the raw transport for mesh communication (MQTT, UDP, etc.).
	Transport raw.RawTransport

	// NodeID is this node's identity.
	NodeID core.NodeID
	// LongName is the display name.
	LongName string
	// ShortName is the short display name.
	ShortName string
	// HwModel is the hardware model reported to clients and in broadcasts.
	// Defaults to HardwareModel_PRIVATE_HW if zero.
	HwModel pb.HardwareModel

	// Channels is the channel set for mesh communication.
	Channels *pb.ChannelSet

	// BroadcastNodeInfoInterval for periodic NodeInfo broadcasts.
	// Zero disables.
	BroadcastNodeInfoInterval time.Duration
	// BroadcastPositionInterval for periodic Position broadcasts.
	// Zero disables.
	BroadcastPositionInterval time.Duration

	// Position coordinates.
	PositionLatitudeI  int32
	PositionLongitudeI int32
	PositionAltitude   int32

	// TCPListenAddr for the client API TCP listener. Empty disables.
	TCPListenAddr string

	// PrivateKeyFunc returns the X25519 private key for a node this device manages.
	// Return nil if the node is not managed. If nil, PKI decryption is disabled.
	PrivateKeyFunc func(nodeID core.NodeID) []byte

	// PublicKeyFunc returns the X25519 public key for any node.
	// Return nil if unknown. If nil, PKI decryption is disabled.
	PublicKeyFunc func(nodeID core.NodeID) []byte

	// EventHandlers are called for decoded mesh events. Optional.
	EventHandlers []event.Handler

	// Logger for node events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

func (c *Config) validate() error {
	if c.Transport == nil {
		return fmt.Errorf("Transport is required")
	}
	if c.NodeID == 0 {
		return fmt.Errorf("NodeID is required")
	}
	if c.Channels == nil {
		return fmt.Errorf("Channels is required")
	}
	if len(c.Channels.Settings) == 0 {
		return fmt.Errorf("Channels.Settings should be non-empty")
	}
	if c.LongName == "" {
		c.LongName = c.NodeID.DefaultLongName()
	}
	if c.ShortName == "" {
		c.ShortName = c.NodeID.DefaultShortName()
	}
	if c.HwModel == pb.HardwareModel_UNSET {
		c.HwModel = pb.HardwareModel_PRIVATE_HW
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// Node is an emulated Meshtastic node that wires together a nodedb,
// broadcast scheduler, and client API server over a raw transport.
type Node struct {
	cfg       Config
	log       *slog.Logger
	transport raw.RawTransport

	db        *nodedb.NodeDB
	channels  *core.ChannelRegistry
	dedup     *dedupe.PacketDeduplicator
	scheduler *broadcast.Scheduler
	api       *clientapi.Server
	packetIDs packetIDGenerator

	eventMu       sync.RWMutex
	eventHandlers []event.Handler
}

// New creates a Node with the given configuration. It validates the config,
// constructs all sub-components, and wires their callbacks.
func New(cfg Config) (*Node, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	n := &Node{
		cfg:       cfg,
		log:       cfg.Logger.WithGroup("node").With("node", cfg.NodeID.String()),
		transport: cfg.Transport,
		dedup:     dedupe.NewDeduplicator(2 * time.Hour),
	}

	// Seed event handlers from config
	if len(cfg.EventHandlers) > 0 {
		n.eventHandlers = append(n.eventHandlers, cfg.EventHandlers...)
	}

	// Build channel registry from configured channels
	n.channels = core.NewChannelRegistry()
	for _, settings := range cfg.Channels.Settings {
		if ch := core.ChannelFromSettings(settings); ch != nil {
			n.channels.Register(ch)
		}
	}

	// Create nodedb
	n.db = nodedb.New(nodedb.Config{
		SelfNode:  cfg.NodeID,
		LongName:  cfg.LongName,
		ShortName: cfg.ShortName,
		Logger:    cfg.Logger,
	})

	// Create broadcast scheduler — closure wraps sendPacket with empty channel (primary)
	n.scheduler = broadcast.New(broadcast.Config{
		NodeID:             cfg.NodeID,
		LongName:           cfg.LongName,
		ShortName:          cfg.ShortName,
		HwModel:            cfg.HwModel,
		NodeInfoInterval:   cfg.BroadcastNodeInfoInterval,
		PositionInterval:   cfg.BroadcastPositionInterval,
		PositionLatitudeI:  cfg.PositionLatitudeI,
		PositionLongitudeI: cfg.PositionLongitudeI,
		PositionAltitude:   cfg.PositionAltitude,
		Send: func(ctx context.Context, pkt *pb.MeshPacket) error {
			return n.sendPacket(ctx, pkt, "")
		},
		Logger: cfg.Logger,
	})

	// Create client API server — resolve channel name from hash for outbound packets
	n.api = clientapi.New(clientapi.Config{
		NodeID:                cfg.NodeID,
		LongName:              cfg.LongName,
		ShortName:             cfg.ShortName,
		Channels:              cfg.Channels,
		NodeInfoBroadcastSecs: uint32(cfg.BroadcastNodeInfoInterval.Seconds()),
		Nodes:                 n.db,
		NextPacketID:          n.packetIDs.next,
		OnOutboundPacket: func(ctx context.Context, pkt *pb.MeshPacket) {
			channelName := n.channels.LookupName(pkt.Channel)
			if err := n.sendPacket(ctx, pkt, channelName); err != nil {
				n.log.Error("failed to send outbound packet", "error", err)
			}
		},
		TCPListenAddr: cfg.TCPListenAddr,
		Logger:        cfg.Logger,
	})

	return n, nil
}

// Run starts all components and the transport. It blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	// Install packet handler on the transport
	n.transport.SetPacketHandler(n.handleIncomingPacket)

	// Subscribe to configured channels
	for _, ch := range n.cfg.Channels.Settings {
		n.log.Debug("subscribing to channel", "channel", ch.Name)
		n.transport.AddChannel(ch.Name)
	}

	// Start the transport
	if err := n.transport.Start(ctx); err != nil {
		return fmt.Errorf("starting transport: %w", err)
	}

	eg, egCtx := errgroup.WithContext(ctx)

	// Start broadcast scheduler
	eg.Go(func() error {
		n.scheduler.Start(egCtx)
		return nil
	})

	// Start client API server
	eg.Go(func() error {
		n.api.Start(egCtx)
		return nil
	})

	return eg.Wait()
}

// Conn returns an in-memory client connection to this node.
func (n *Node) Conn(ctx context.Context) net.Conn {
	return n.api.Conn(ctx)
}

// NodeDB returns the node's database for external inspection.
func (n *Node) NodeDB() *nodedb.NodeDB {
	return n.db
}

// OnEvent registers an event handler. Handlers are called synchronously
// for each decoded packet. Safe to call from multiple goroutines.
func (n *Node) OnEvent(fn event.Handler) {
	n.eventMu.Lock()
	defer n.eventMu.Unlock()
	n.eventHandlers = append(n.eventHandlers, fn)
}

func (n *Node) emitEvent(evt any) {
	n.eventMu.RLock()
	handlers := n.eventHandlers
	n.eventMu.RUnlock()
	for _, fn := range handlers {
		fn(evt)
	}
}

// sendPacket stamps a packet ID and sends via the specified channel.
// If channelName is empty, the primary channel is used.
func (n *Node) sendPacket(_ context.Context, packet *pb.MeshPacket, channelName string) error {
	packet.Id = n.packetIDs.next()
	if channelName == "" {
		channelName = n.cfg.Channels.Settings[0].Name
	}
	return n.transport.SendPacket(channelName, packet)
}

// handleIncomingPacket is the full incoming packet pipeline:
//  1. Deduplicate
//  2. Forward raw packet to connected clients
//  3. Decrypt (PKI or PSK) and process
func (n *Node) handleIncomingPacket(pkt transport.NetworkPacket) {
	// 1. Deduplicate
	if pkt.Packet.Id != 0 && n.dedup.Seen(pkt.Packet.From, pkt.Packet.Id) {
		n.log.Debug("dropping duplicate packet",
			"from", core.NodeID(pkt.Packet.From),
			"packetID", pkt.Packet.Id)
		return
	}

	// 2. Forward raw packet to all connected clients (before decryption)
	n.api.DispatchToClients(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Packet{
			Packet: pkt.Packet,
		},
	})

	// 3. If already decoded, process directly
	if decoded := pkt.Packet.GetDecoded(); decoded != nil {
		channelName := n.channels.LookupName(pkt.Packet.Channel)
		n.processDecoded(pkt, decoded, channelName, false)
		return
	}

	// 4. Try PKI decryption (channel==0, unicast to managed node)
	if n.shouldTryPKI(pkt.Packet) {
		data, err := n.tryDecryptPKI(pkt.Packet)
		if err == nil && data != nil {
			n.processDecoded(pkt, data, "PKI", true)
			return
		}
		n.log.Debug("PKI decryption failed, falling back to PSK", "error", err)
	}

	// 5. Try PSK decryption via channel registry
	ch, ok := n.channels.Lookup(pkt.Packet.Channel)
	if !ok {
		n.log.Debug("unknown channel hash", "hash", pkt.Packet.Channel)
		return
	}

	data, err := crypto.TryDecode(pkt.Packet, ch.GetKeyBytes())
	if err != nil {
		n.log.Debug("PSK decryption failed",
			"channel", ch.GetName(),
			"error", err)
		return
	}

	n.processDecoded(pkt, data, ch.GetName(), false)
}

// processDecoded handles a successfully decoded packet: updates the nodedb
// and emits typed events.
func (n *Node) processDecoded(pkt transport.NetworkPacket, data *pb.Data, channelName string, isPKI bool) {
	base := event.Event{
		ChannelName: channelName,
		From:        core.NodeID(pkt.Packet.From),
		To:          core.NodeID(pkt.Packet.To),
		Timestamp:   time.Now(),
		PacketID:    pkt.Packet.Id,
		Portnum:     data.Portnum,
		IsPKI:       isPKI,
		RawData:     data,
	}
	if pkt.Packet.RxTime > 0 {
		base.Timestamp = time.Unix(int64(pkt.Packet.RxTime), 0)
	}

	from := pkt.Packet.From

	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			n.log.Debug("failed to unmarshal NodeInfo", "error", err)
			return
		}
		n.db.Update(from, func(info *pb.NodeInfo) { info.User = user })
		n.emitEvent(&event.NodeInfoUpdated{Event: base, User: user})

	case pb.PortNum_POSITION_APP:
		pos := &pb.Position{}
		if err := proto.Unmarshal(data.Payload, pos); err != nil {
			n.log.Debug("failed to unmarshal Position", "error", err)
			return
		}
		n.db.Update(from, func(info *pb.NodeInfo) { info.Position = pos })
		n.emitEvent(&event.PositionUpdated{Event: base, Position: pos})

	case pb.PortNum_TELEMETRY_APP:
		tel := &pb.Telemetry{}
		if err := proto.Unmarshal(data.Payload, tel); err != nil {
			n.log.Debug("failed to unmarshal Telemetry", "error", err)
			return
		}
		if metrics := tel.GetDeviceMetrics(); metrics != nil {
			n.db.Update(from, func(info *pb.NodeInfo) { info.DeviceMetrics = metrics })
		}
		n.emitEvent(&event.TelemetryUpdated{Event: base, Telemetry: tel})

	case pb.PortNum_TEXT_MESSAGE_APP:
		n.emitEvent(&event.TextMessage{
			Event:   base,
			Message: string(data.Payload),
			IsDM:    !core.NodeID(pkt.Packet.To).IsBroadcast(),
			ReplyID: data.ReplyId,
			Emoji:   data.Emoji,
		})

	default:
		n.emitEvent(&event.PacketReceived{Event: base})
	}
}
