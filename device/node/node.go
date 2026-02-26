// Package node provides the glue that wires together the device components
// (nodedb, broadcast, clientapi) over a raw transport to form a complete
// emulated Meshtastic node.
package node

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/broadcast"
	"github.com/kabili207/meshtastic-go/device/clientapi"
	"github.com/kabili207/meshtastic-go/device/nodedb"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/raw"
	"golang.org/x/sync/errgroup"
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
	scheduler *broadcast.Scheduler
	api       *clientapi.Server
	packetIDs packetIDGenerator
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
	}

	// Create nodedb
	n.db = nodedb.New(nodedb.Config{
		SelfNode:  cfg.NodeID,
		LongName:  cfg.LongName,
		ShortName: cfg.ShortName,
		Logger:    cfg.Logger,
	})

	// Create broadcast scheduler with sendPacket as the SendFunc
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
		Send:               n.sendPacket,
		Logger:             cfg.Logger,
	})

	// Create client API server
	n.api = clientapi.New(clientapi.Config{
		NodeID:                cfg.NodeID,
		LongName:              cfg.LongName,
		ShortName:             cfg.ShortName,
		Channels:              cfg.Channels,
		NodeInfoBroadcastSecs: uint32(cfg.BroadcastNodeInfoInterval.Seconds()),
		Nodes:                 n.db,
		NextPacketID:          n.packetIDs.next,
		OnOutboundPacket: func(ctx context.Context, pkt *pb.MeshPacket) {
			if err := n.sendPacket(ctx, pkt); err != nil {
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

// sendPacket stamps a packet ID and sends via the primary channel.
func (n *Node) sendPacket(_ context.Context, packet *pb.MeshPacket) error {
	packet.Id = n.packetIDs.next()
	channelName := n.cfg.Channels.Settings[0].Name
	return n.transport.SendPacket(channelName, packet)
}

// handleIncomingPacket processes packets from the transport:
// 1. Dispatches to clientapi for connected clients
// 2. Dispatches to nodedb for tracking updates (primary channel only)
func (n *Node) handleIncomingPacket(pkt transport.NetworkPacket) {
	// Forward raw packet to all connected clients
	n.api.DispatchToClients(&pb.FromRadio{
		PayloadVariant: &pb.FromRadio_Packet{
			Packet: pkt.Packet,
		},
	})

	// Feed to nodedb for tracking (primary channel only)
	if len(n.cfg.Channels.Settings) > 0 {
		primary := n.cfg.Channels.Settings[0]
		if pkt.Channel == primary.Name {
			n.db.ProcessPacket(pkt.Packet, primary.Psk)
		}
	}
}
