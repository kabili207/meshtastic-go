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

	// PrivateKey is the X25519 private key for this node. If nil, PKI is disabled.
	PrivateKey []byte

	// PublicKey is the X25519 public key for this node. If nil, PKI is disabled.
	PublicKey []byte

	// DefaultHopLimit for outbound packets. If zero, defaults to 3.
	// The maximum usable value is 7.
	DefaultHopLimit uint32

	// OkToMQTT sets the "OK to MQTT" bitfield flag on all outbound Data
	// packets. When true, MQTT gateways on the mesh are permitted to
	// upload these packets.
	OkToMQTT bool

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
	if c.DefaultHopLimit == 0 {
		c.DefaultHopLimit = 3
	}
	if c.DefaultHopLimit > 7 {
		c.DefaultHopLimit = 7
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// Node is an emulated Meshtastic node that wires together a nodedb,
// broadcast scheduler, and client API server over a raw transport.
type Node struct {
	base baseNode
	cfg  Config

	db        *nodedb.NodeDB
	scheduler *broadcast.Scheduler
	api       *clientapi.Server
}

// New creates a Node with the given configuration. It validates the config,
// constructs all sub-components, and wires their callbacks.
func New(cfg Config) (*Node, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	logger := cfg.Logger.WithGroup("node").With("node", cfg.NodeID.String())

	// Build channel registry from configured channels
	channels := core.NewChannelRegistry()
	for _, settings := range cfg.Channels.Settings {
		if ch := core.ChannelFromSettings(settings); ch != nil {
			channels.Register(ch)
		}
	}

	n := &Node{
		base: baseNode{
			transport:      cfg.Transport,
			channels:       channels,
			dedup:          dedupe.NewDeduplicator(2 * time.Hour),
			throttle:       newRequestThrottle(),
			log:            logger,
			nodeID:         cfg.NodeID,
			okToMQTT:       cfg.OkToMQTT,
			hopLimit:       cfg.DefaultHopLimit,
			primaryChannel: cfg.Channels.Settings[0].Name,
		},
		cfg: cfg,
	}

	// Seed event handlers from config
	if len(cfg.EventHandlers) > 0 {
		n.base.eventHandlers = append(n.base.eventHandlers, cfg.EventHandlers...)
	}

	// Create nodedb
	n.db = nodedb.New(nodedb.Config{
		SelfNode:  cfg.NodeID,
		LongName:  cfg.LongName,
		ShortName: cfg.ShortName,
		Logger:    cfg.Logger,
	})

	// Create broadcast scheduler — Node methods handle packet construction
	n.scheduler = broadcast.New(broadcast.Config{
		NodeInfoInterval: cfg.BroadcastNodeInfoInterval,
		NodeInfoFunc:     n.broadcastNodeInfo,
		PositionInterval: cfg.BroadcastPositionInterval,
		PositionFunc:     n.broadcastPosition,
		Logger:           cfg.Logger,
	})

	// Create client API server — resolve channel name from hash for outbound packets
	n.api = clientapi.New(clientapi.Config{
		NodeID:                cfg.NodeID,
		LongName:              cfg.LongName,
		ShortName:             cfg.ShortName,
		Channels:              cfg.Channels,
		NodeInfoBroadcastSecs: uint32(cfg.BroadcastNodeInfoInterval.Seconds()),
		Nodes:                 n.db,
		NextPacketID:          n.base.packetIDs.next,
		OnOutboundPacket: func(ctx context.Context, pkt *pb.MeshPacket) {
			channelName := n.base.channels.LookupName(pkt.Channel)
			if err := n.base.sendPacket(ctx, pkt, channelName); err != nil {
				n.base.log.Error("failed to send outbound packet", "error", err)
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
	n.base.transport.SetPacketHandler(n.handleIncomingPacket)

	// Subscribe to configured channels
	for _, ch := range n.cfg.Channels.Settings {
		n.base.log.Debug("subscribing to channel", "channel", ch.Name)
		n.base.transport.AddChannel(ch.Name)
	}

	// Start the transport
	if err := n.base.transport.Start(ctx); err != nil {
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
	n.base.OnEvent(fn)
}

// buildNodeInfoData returns a marshalled NodeInfo payload. This is the single
// source of truth for NodeInfo construction — used by both periodic broadcasts
// and WantResponse replies. Pass requestID=0 for unsolicited broadcasts.
func (n *Node) buildNodeInfoData(requestID uint32) *pb.Data {
	user := &pb.User{
		Id:        n.cfg.NodeID.String(),
		LongName:  n.cfg.LongName,
		ShortName: n.cfg.ShortName,
		HwModel:   n.cfg.HwModel,
		PublicKey: n.cfg.PublicKey,
	}
	userBytes, err := proto.Marshal(user)
	if err != nil {
		n.base.log.Error("failed to marshal NodeInfo", "error", err)
		return nil
	}
	data := &pb.Data{
		Portnum: pb.PortNum_NODEINFO_APP,
		Payload: userBytes,
	}
	if requestID != 0 {
		data.RequestId = requestID
	}
	return data
}

// broadcastNodeInfo sends a NodeInfo broadcast to all nodes.
func (n *Node) broadcastNodeInfo(ctx context.Context) error {
	n.base.log.Debug("broadcasting NodeInfo")
	data := n.buildNodeInfoData(0)
	if data == nil {
		return fmt.Errorf("building NodeInfo data")
	}
	return n.base.sendPacket(ctx, &pb.MeshPacket{
		From:           n.cfg.NodeID.Uint32(),
		To:             core.BroadcastNodeID.Uint32(),
		Priority:       pb.MeshPacket_BACKGROUND,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}, "")
}

// broadcastPosition sends a Position broadcast to all nodes.
func (n *Node) broadcastPosition(ctx context.Context) error {
	n.base.log.Debug("broadcasting Position")
	pos := &pb.Position{
		LatitudeI:  &n.cfg.PositionLatitudeI,
		LongitudeI: &n.cfg.PositionLongitudeI,
		Altitude:   &n.cfg.PositionAltitude,
		Time:       uint32(time.Now().Unix()),
	}
	posBytes, err := proto.Marshal(pos)
	if err != nil {
		return fmt.Errorf("marshalling position: %w", err)
	}
	return n.base.sendPacket(ctx, &pb.MeshPacket{
		From:     n.cfg.NodeID.Uint32(),
		To:       core.BroadcastNodeID.Uint32(),
		Priority: pb.MeshPacket_BACKGROUND,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_POSITION_APP,
				Payload: posBytes,
			},
		},
	}, "")
}

// respondNodeInfo sends our NodeInfo as a unicast response to a WantResponse request.
func (n *Node) respondNodeInfo(to uint32, requestID uint32) {
	data := n.buildNodeInfoData(requestID)
	if data == nil {
		return
	}
	pkt := &pb.MeshPacket{
		From:           n.cfg.NodeID.Uint32(),
		To:             to,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}
	if err := n.base.sendPacket(context.Background(), pkt, ""); err != nil {
		n.base.log.Error("failed to send NodeInfo response", "to", core.NodeID(to), "error", err)
	} else {
		n.base.log.Debug("sent NodeInfo response", "to", core.NodeID(to))
	}
}

// respondPosition sends our Position as a unicast response to a WantResponse request.
func (n *Node) respondPosition(to uint32, requestID uint32) {
	pos := &pb.Position{
		LatitudeI:  &n.cfg.PositionLatitudeI,
		LongitudeI: &n.cfg.PositionLongitudeI,
		Altitude:   &n.cfg.PositionAltitude,
		Time:       uint32(time.Now().Unix()),
	}
	posBytes, err := proto.Marshal(pos)
	if err != nil {
		n.base.log.Error("failed to marshal Position response", "error", err)
		return
	}
	pkt := &pb.MeshPacket{
		From: n.cfg.NodeID.Uint32(),
		To:   to,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum:   pb.PortNum_POSITION_APP,
				Payload:   posBytes,
				RequestId: requestID,
			},
		},
	}
	if err := n.base.sendPacket(context.Background(), pkt, ""); err != nil {
		n.base.log.Error("failed to send Position response", "to", core.NodeID(to), "error", err)
	} else {
		n.base.log.Debug("sent Position response", "to", core.NodeID(to))
	}
}

// handleIncomingPacket is the full incoming packet pipeline:
//  1. Deduplicate
//  2. Forward raw packet to connected clients
//  3. Decrypt (PKI or PSK) and process
func (n *Node) handleIncomingPacket(pkt transport.NetworkPacket) {
	// 1. Deduplicate
	if pkt.Packet.Id != 0 && n.base.dedup.Seen(pkt.Packet.From, pkt.Packet.Id) {
		n.base.log.Debug("dropping duplicate packet",
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
		channelName := n.base.channels.LookupName(pkt.Packet.Channel)
		n.processDecoded(pkt, decoded, channelName, false)
		return
	}

	// 4. Try PKI decryption (channel==0, unicast to this node)
	if n.shouldTryPKI(pkt.Packet) {
		data, err := n.tryDecryptPKI(pkt.Packet)
		if err == nil && data != nil {
			n.processDecoded(pkt, data, "PKI", true)
			return
		}
		n.base.log.Debug("PKI decryption failed, falling back to PSK", "error", err)
	}

	// 5. Try PSK decryption via channel registry
	ch, ok := n.base.channels.Lookup(pkt.Packet.Channel)
	if !ok {
		n.base.log.Debug("unknown channel hash", "hash", pkt.Packet.Channel)
		return
	}

	data, err := crypto.TryDecode(pkt.Packet, ch.GetKeyBytes())
	if err != nil {
		n.base.log.Debug("PSK decryption failed",
			"channel", ch.GetName(),
			"error", err)
		return
	}

	n.processDecoded(pkt, data, ch.GetName(), false)
}

// processDecoded handles a successfully decoded packet: updates the nodedb
// and emits typed events.
func (n *Node) processDecoded(pkt transport.NetworkPacket, data *pb.Data, channelName string, isPKI bool) {
	evt := event.Event{
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
		evt.Timestamp = time.Unix(int64(pkt.Packet.RxTime), 0)
	}

	from := pkt.Packet.From

	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			n.base.log.Debug("failed to unmarshal NodeInfo", "error", err)
			return
		}
		n.db.Update(from, func(info *pb.NodeInfo) { info.User = user })
		n.base.emitEvent(&event.NodeInfoUpdated{Event: evt, User: user})

		// Respond to NodeInfo requests with our own NodeInfo
		if data.WantResponse && n.base.throttle.canRespond(core.NodeID(from), pb.PortNum_NODEINFO_APP) {
			n.respondNodeInfo(from, pkt.Packet.Id)
		}

	case pb.PortNum_POSITION_APP:
		pos := &pb.Position{}
		if err := proto.Unmarshal(data.Payload, pos); err != nil {
			n.base.log.Debug("failed to unmarshal Position", "error", err)
			return
		}
		n.db.Update(from, func(info *pb.NodeInfo) { info.Position = pos })
		n.base.emitEvent(&event.PositionUpdated{Event: evt, Position: pos})

		// Respond to Position requests with our position
		if data.WantResponse && n.base.throttle.canRespond(core.NodeID(from), pb.PortNum_POSITION_APP) {
			n.respondPosition(from, pkt.Packet.Id)
		}

	case pb.PortNum_TELEMETRY_APP:
		tel := &pb.Telemetry{}
		if err := proto.Unmarshal(data.Payload, tel); err != nil {
			n.base.log.Debug("failed to unmarshal Telemetry", "error", err)
			return
		}
		if metrics := tel.GetDeviceMetrics(); metrics != nil {
			n.db.Update(from, func(info *pb.NodeInfo) { info.DeviceMetrics = metrics })
		}
		n.base.emitEvent(&event.TelemetryUpdated{Event: evt, Telemetry: tel})

	case pb.PortNum_TEXT_MESSAGE_APP:
		n.base.emitEvent(&event.TextMessage{
			Event:   evt,
			Message: string(data.Payload),
			IsDM:    !core.NodeID(pkt.Packet.To).IsBroadcast(),
			ReplyID: data.ReplyId,
			Emoji:   data.Emoji,
		})

	case pb.PortNum_WAYPOINT_APP:
		wp := &pb.Waypoint{}
		if err := proto.Unmarshal(data.Payload, wp); err != nil {
			n.base.log.Debug("failed to unmarshal Waypoint", "error", err)
			return
		}
		isDelete := wp.Expire > 0 && time.Unix(int64(wp.Expire), 0).Before(time.Now())
		n.base.emitEvent(&event.WaypointReceived{Event: evt, Waypoint: wp, IsDelete: isDelete})

	case pb.PortNum_NEIGHBORINFO_APP:
		ni := &pb.NeighborInfo{}
		if err := proto.Unmarshal(data.Payload, ni); err != nil {
			n.base.log.Debug("failed to unmarshal NeighborInfo", "error", err)
			return
		}
		n.base.emitEvent(&event.NeighborInfoReceived{Event: evt, NeighborInfo: ni})

	case pb.PortNum_MAP_REPORT_APP:
		mr := &pb.MapReport{}
		if err := proto.Unmarshal(data.Payload, mr); err != nil {
			n.base.log.Debug("failed to unmarshal MapReport", "error", err)
			return
		}
		// Update NodeDB with position and user info from map report.
		n.db.Update(from, func(info *pb.NodeInfo) {
			if info.Position == nil {
				info.Position = &pb.Position{}
			}
			info.Position.LatitudeI = &mr.LatitudeI
			info.Position.LongitudeI = &mr.LongitudeI
			if mr.Altitude != 0 {
				info.Position.Altitude = &mr.Altitude
			}
			if info.User == nil {
				info.User = &pb.User{}
			}
			if mr.LongName != "" {
				info.User.LongName = mr.LongName
			}
			if mr.ShortName != "" {
				info.User.ShortName = mr.ShortName
			}
			info.User.HwModel = mr.HwModel
			info.User.Role = mr.Role
		})
		n.base.emitEvent(&event.MapReportReceived{Event: evt, MapReport: mr})

	case pb.PortNum_TRACEROUTE_APP:
		rd := &pb.RouteDiscovery{}
		if err := proto.Unmarshal(data.Payload, rd); err != nil {
			n.base.log.Debug("failed to unmarshal RouteDiscovery", "error", err)
			return
		}
		isRequest := data.WantResponse
		n.base.emitEvent(&event.TracerouteReceived{Event: evt, RouteDiscovery: rd, IsRequest: isRequest})

	case pb.PortNum_ROUTING_APP:
		routing := &pb.Routing{}
		if err := proto.Unmarshal(data.Payload, routing); err != nil {
			n.base.log.Debug("failed to unmarshal Routing", "error", err)
			return
		}
		n.base.emitEvent(&event.RoutingReceived{
			Event:            evt,
			ErrorReason:      routing.GetErrorReason(),
			OriginalPacketID: data.RequestId,
		})

	default:
		n.base.emitEvent(&event.PacketReceived{Event: evt})
	}
}
