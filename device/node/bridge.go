package node

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/dedupe"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/device/nodedb"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/raw"
	"google.golang.org/protobuf/proto"
)

// BridgeConfig configures a BridgeNode.
type BridgeConfig struct {
	// Transport is the raw transport for mesh communication (MQTT, UDP, etc.).
	Transport raw.RawTransport

	// NodeID is the bridge's own identity on the mesh.
	NodeID core.NodeID
	// LongName is the bridge's display name.
	LongName string
	// ShortName is the bridge's short display name.
	ShortName string
	// HwModel is the hardware model reported in broadcasts.
	// Defaults to HardwareModel_PRIVATE_HW if zero.
	HwModel pb.HardwareModel

	// Channels is the channel set for mesh communication.
	Channels *pb.ChannelSet

	// DefaultHopLimit for outbound packets. If zero, defaults to 3.
	// The maximum usable value is 7.
	DefaultHopLimit uint32

	// OkToMQTT sets the "OK to MQTT" bitfield flag on all outbound Data
	// packets. When true, MQTT gateways on the mesh are permitted to
	// upload these packets.
	OkToMQTT bool

	// IsManagedNode returns true if the given NodeID is managed by this bridge.
	// Called for incoming packet routing and self-echo filtering.
	IsManagedNode func(core.NodeID) bool

	// PrivateKeyForNode returns the X25519 private key for a managed node.
	// Return nil if PKI is not available for this node.
	PrivateKeyForNode func(core.NodeID) []byte

	// PublicKeyForNode returns the X25519 public key for a node (managed or remote).
	// Used for both PKI encryption (managed→remote) and decryption (remote→managed).
	PublicKeyForNode func(core.NodeID) []byte

	// NodeInfoForNode returns the long name, short name, and public key for a managed node.
	// Used for auto-responding to NodeInfo WantResponse on behalf of managed nodes.
	// Return ok=false if the node should not auto-respond.
	NodeInfoForNode func(core.NodeID) (longName, shortName string, pubKey []byte, ok bool)

	// NeighborProvider returns the neighbor node IDs for a managed node, used to
	// answer on-demand neighbor info requests. Optional.
	NeighborProvider func(core.NodeID) []core.NodeID

	// NeighborBroadcastInterval is the interval (seconds) reported in neighbor
	// info responses.
	NeighborBroadcastInterval uint32

	// HostMetricsProvider builds a host-metrics Telemetry payload on demand. The
	// bridge does not gather host metrics itself; supply this to answer host
	// metric requests and broadcasts. Optional.
	HostMetricsProvider func() (*pb.Telemetry, error)

	// StartTime is the reference time for device-metrics uptime. Defaults to the
	// time the bridge was created.
	StartTime time.Time

	// OnStateChange is called when the underlying transport's aggregate
	// connection state changes. Optional.
	OnStateChange func(transport.ListenerEvent)

	// EventHandlers are called for decoded mesh events. Optional.
	EventHandlers []event.Handler

	// Logger for node events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

func (c *BridgeConfig) validate() error {
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
	if c.IsManagedNode == nil {
		return fmt.Errorf("IsManagedNode callback is required")
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
		c.DefaultHopLimit = core.DefaultHopLimit
	}
	if c.DefaultHopLimit > core.MaxHops {
		c.DefaultHopLimit = core.MaxHops
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.StartTime.IsZero() {
		c.StartTime = time.Now().UTC()
	}
	return nil
}

// BridgeNode manages multiple virtual Meshtastic identities through a single
// transport connection. It handles sending packets on behalf of managed nodes,
// receiving and decrypting packets addressed to any managed node, and
// auto-responding to WantResponse requests for managed nodes.
//
// Unlike Node (which is a single identity with a broadcast scheduler and
// client API), BridgeNode is designed for bridge/gateway applications that
// need to represent many virtual nodes on the mesh.
type BridgeNode struct {
	base baseNode
	cfg  BridgeConfig
	db   *nodedb.NodeDB
}

// NewBridge creates a BridgeNode with the given configuration.
func NewBridge(cfg BridgeConfig) (*BridgeNode, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	logger := cfg.Logger.WithGroup("bridge").With("node", cfg.NodeID.String())

	// Build channel registry from configured channels
	channels := core.NewChannelRegistry()
	for _, settings := range cfg.Channels.Settings {
		if ch := core.ChannelFromSettings(settings); ch != nil {
			channels.Register(ch)
		}
	}

	b := &BridgeNode{
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
		b.base.eventHandlers = append(b.base.eventHandlers, cfg.EventHandlers...)
	}

	// Create nodedb for tracking remote nodes
	b.db = nodedb.New(nodedb.Config{
		SelfNode:  cfg.NodeID,
		LongName:  cfg.LongName,
		ShortName: cfg.ShortName,
		Logger:    cfg.Logger,
	})

	return b, nil
}

// Run starts the transport and incoming packet pipeline. It blocks until ctx is
// cancelled, then stops the transport before returning.
func (b *BridgeNode) Run(ctx context.Context) error {
	b.base.transport.SetPacketHandler(b.handleIncomingPacket)
	if b.cfg.OnStateChange != nil {
		b.base.transport.SetStateHandler(func(_ transport.Transport, e transport.ListenerEvent) {
			b.cfg.OnStateChange(e)
		})
	}

	// Subscribe to configured channels
	for _, ch := range b.cfg.Channels.Settings {
		b.base.log.Debug("subscribing to channel", "channel", ch.Name)
		b.base.transport.AddChannel(ch.Name)
	}

	if err := b.base.transport.Start(ctx); err != nil {
		return fmt.Errorf("starting transport: %w", err)
	}

	<-ctx.Done()
	_ = b.base.transport.Stop()
	return nil
}

// IsConnected reports whether the underlying transport is connected.
func (b *BridgeNode) IsConnected() bool {
	return b.base.transport.IsConnected()
}

// AddChannel registers an additional channel at runtime and subscribes the
// transport to it. keyStr is the base64-encoded PSK (or short PSK).
func (b *BridgeNode) AddChannel(name, keyStr string) error {
	ch, err := core.NewChannel(name, keyStr)
	if err != nil {
		return fmt.Errorf("creating channel %q: %w", name, err)
	}
	b.base.channels.Register(ch)
	b.base.transport.AddChannel(name)
	return nil
}

// NodeDB returns the bridge's node database for external inspection.
func (b *BridgeNode) NodeDB() *nodedb.NodeDB {
	return b.db
}

// OnEvent registers an event handler. Handlers are called synchronously
// for each decoded packet. Safe to call from multiple goroutines.
func (b *BridgeNode) OnEvent(fn event.Handler) {
	b.base.OnEvent(fn)
}

// handleIncomingPacket is the full incoming packet pipeline for BridgeNode:
//  1. Deduplicate
//  2. Self-echo filter (drop packets from managed nodes)
//  3. Decrypt (PKI for managed nodes, or PSK) and process
func (b *BridgeNode) handleIncomingPacket(pkt transport.NetworkPacket) {
	// 1. Deduplicate
	if pkt.Packet.Id != 0 && b.base.dedup.Seen(pkt.Packet.From, pkt.Packet.Id) {
		b.base.log.Debug("dropping duplicate packet",
			"from", core.NodeID(pkt.Packet.From),
			"packetID", pkt.Packet.Id)
		return
	}

	// 2. Self-echo filter: drop packets where From is a managed node
	from := core.NodeID(pkt.Packet.From)
	if b.cfg.IsManagedNode(from) {
		b.base.log.Debug("dropping self-echo from managed node", "from", from)
		return
	}

	// 3. If already decoded, process directly
	if decoded := pkt.Packet.GetDecoded(); decoded != nil {
		channelName := b.base.channels.LookupName(pkt.Packet.Channel)
		b.processDecoded(pkt, decoded, channelName, nil, false, 0)
		return
	}

	// 4. Try PKI decryption if addressed to a managed node
	to := core.NodeID(pkt.Packet.To)
	if b.shouldTryPKI(pkt.Packet) {
		data, err := b.tryDecryptPKI(pkt.Packet)
		if err == nil && data != nil {
			b.processDecoded(pkt, data, "PKI", nil, true, to)
			return
		}
		b.base.log.Debug("PKI decryption failed, falling back to PSK", "error", err)
	}

	// 5. Try PSK decryption via channel registry
	ch, ok := b.base.channels.Lookup(pkt.Packet.Channel)
	if !ok {
		b.base.log.Debug("unknown channel hash", "hash", pkt.Packet.Channel)
		return
	}

	data, err := crypto.TryDecode(pkt.Packet, ch.GetKeyBytes())
	if err != nil {
		b.base.log.Debug("PSK decryption failed",
			"channel", ch.GetName(),
			"error", err)
		return
	}

	channelKey := ch.GetKeyString()
	b.processDecoded(pkt, data, ch.GetName(), &channelKey, false, 0)
}

// gatewayNode derives the node that delivered this packet. For MQTT it is the
// gateway ID from the service envelope; for radio/UDP it is derived from the
// relay node, falling back to the sender when the packet arrived directly.
func gatewayNode(pkt transport.NetworkPacket) core.NodeID {
	if pkt.GatewayID != "" {
		if id, err := core.ParseNodeID(pkt.GatewayID); err == nil {
			return id
		}
	}
	p := pkt.Packet
	if p.HopStart == p.HopLimit && p.RelayNode == (p.From&0xFF) {
		return core.NodeID(p.From)
	}
	return core.NodeID(p.RelayNode)
}

// shouldTryPKI returns true if the packet should be attempted for PKI decryption.
// For BridgeNode, this checks if the destination is any managed node.
func (b *BridgeNode) shouldTryPKI(pkt *pb.MeshPacket) bool {
	if _, ok := pkt.PayloadVariant.(*pb.MeshPacket_Encrypted); !ok {
		return false
	}
	to := core.NodeID(pkt.To)
	return pkt.Channel == 0 &&
		pkt.To > 0 &&
		!to.IsBroadcast() &&
		b.cfg.IsManagedNode(to)
}

// tryDecryptPKI attempts PKI decryption using the managed node's private key.
func (b *BridgeNode) tryDecryptPKI(pkt *pb.MeshPacket) (*pb.Data, error) {
	to := core.NodeID(pkt.To)
	from := core.NodeID(pkt.From)

	if b.cfg.PrivateKeyForNode == nil {
		return nil, fmt.Errorf("PrivateKeyForNode not configured")
	}
	privKey := b.cfg.PrivateKeyForNode(to)
	if privKey == nil {
		return nil, fmt.Errorf("no private key for managed node %s", to)
	}

	if b.cfg.PublicKeyForNode == nil {
		return nil, fmt.Errorf("PublicKeyForNode not configured")
	}
	pubKey := b.cfg.PublicKeyForNode(from)
	if pubKey == nil {
		return nil, fmt.Errorf("no public key for sender %s", from)
	}

	return crypto.TryDecodePKI(pkt, pubKey, privKey)
}

// processDecoded handles a successfully decoded packet: updates the nodedb,
// handles WantResponse auto-replies for managed nodes, and emits typed events.
// channelKey is the base64 PSK key the packet was decrypted with (nil for PKI
// or already-decoded packets). managedTo is the managed node this packet was
// addressed to (for PKI unicast), or 0 for PSK/broadcast packets.
func (b *BridgeNode) processDecoded(pkt transport.NetworkPacket, data *pb.Data, channelName string, channelKey *string, isPKI bool, managedTo core.NodeID) {
	via := gatewayNode(pkt)
	evt := event.Event{
		ChannelName:   channelName,
		ChannelKey:    channelKey,
		From:          core.NodeID(pkt.Packet.From),
		To:            core.NodeID(pkt.Packet.To),
		Via:           via,
		Timestamp:     time.Now(),
		PacketID:      pkt.Packet.Id,
		Portnum:       data.Portnum,
		IsPKI:         isPKI,
		RawData:       data,
		ManagedNodeID: managedTo,
		WantAck:       pkt.Packet.WantAck,
		WantResponse:  data.WantResponse,
		IsNeighbor: pkt.Source != transport.PacketSourceMQTT &&
			pkt.Packet.HopStart == pkt.Packet.HopLimit && !pkt.Packet.ViaMqtt,
	}
	if pkt.Packet.RxTime > 0 {
		evt.Timestamp = time.Unix(int64(pkt.Packet.RxTime), 0)
	}

	// reqCtx carries the raw-packet fields the request responders need.
	reqCtx := eventContext{
		From:        evt.From,
		To:          evt.To,
		Via:         via,
		PacketID:    evt.PacketID,
		ChannelName: channelName,
		WantAck:     pkt.Packet.WantAck,
		HopStart:    pkt.Packet.HopStart,
		HopLimit:    pkt.Packet.HopLimit,
		RxSnr:       pkt.Packet.RxSnr,
	}

	from := pkt.Packet.From

	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			b.base.log.Debug("failed to unmarshal NodeInfo", "error", err)
			return
		}
		b.db.Update(from, func(info *pb.NodeInfo) { info.User = user })
		b.base.emitEvent(&event.NodeInfoUpdated{Event: evt, User: user})

		// Auto-respond to NodeInfo WantResponse on behalf of managed nodes
		if data.WantResponse {
			b.respondNodeInfoForManaged(evt)
		}

	case pb.PortNum_POSITION_APP:
		pos := &pb.Position{}
		if err := proto.Unmarshal(data.Payload, pos); err != nil {
			b.base.log.Debug("failed to unmarshal Position", "error", err)
			return
		}
		b.db.Update(from, func(info *pb.NodeInfo) { info.Position = pos })
		b.base.emitEvent(&event.PositionUpdated{Event: evt, Position: pos})

	case pb.PortNum_TELEMETRY_APP:
		tel := &pb.Telemetry{}
		if err := proto.Unmarshal(data.Payload, tel); err != nil {
			b.base.log.Debug("failed to unmarshal Telemetry", "error", err)
			return
		}
		if metrics := tel.GetDeviceMetrics(); metrics != nil {
			b.db.Update(from, func(info *pb.NodeInfo) { info.DeviceMetrics = metrics })
		}
		b.base.emitEvent(&event.TelemetryUpdated{Event: evt, Telemetry: tel})

		// Auto-respond to telemetry requests addressed to a managed node.
		if data.WantResponse && !evt.To.IsBroadcast() {
			b.respondTelemetry(reqCtx, tel)
		}

	case pb.PortNum_TEXT_MESSAGE_APP:
		b.base.emitEvent(&event.TextMessage{
			Event:   evt,
			Message: string(data.Payload),
			IsDM:    !core.NodeID(pkt.Packet.To).IsBroadcast(),
			ReplyID: data.ReplyId,
			Emoji:   data.Emoji,
		})

	case pb.PortNum_WAYPOINT_APP:
		wp := &pb.Waypoint{}
		if err := proto.Unmarshal(data.Payload, wp); err != nil {
			b.base.log.Debug("failed to unmarshal Waypoint", "error", err)
			return
		}
		isDelete := wp.Expire > 0 && time.Unix(int64(wp.Expire), 0).Before(time.Now())
		b.base.emitEvent(&event.WaypointReceived{Event: evt, Waypoint: wp, IsDelete: isDelete})

	case pb.PortNum_NEIGHBORINFO_APP:
		ni := &pb.NeighborInfo{}
		if err := proto.Unmarshal(data.Payload, ni); err != nil {
			b.base.log.Debug("failed to unmarshal NeighborInfo", "error", err)
			return
		}
		b.base.emitEvent(&event.NeighborInfoReceived{Event: evt, NeighborInfo: ni})

		// Auto-respond to neighbor info requests addressed to a managed node.
		if data.WantResponse && !evt.To.IsBroadcast() {
			b.respondNeighborInfo(reqCtx, ni)
		}

	case pb.PortNum_MAP_REPORT_APP:
		mr := &pb.MapReport{}
		if err := proto.Unmarshal(data.Payload, mr); err != nil {
			b.base.log.Debug("failed to unmarshal MapReport", "error", err)
			return
		}
		b.db.Update(from, func(info *pb.NodeInfo) {
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
		b.base.emitEvent(&event.MapReportReceived{Event: evt, MapReport: mr})

	case pb.PortNum_TRACEROUTE_APP:
		rd := &pb.RouteDiscovery{}
		if err := proto.Unmarshal(data.Payload, rd); err != nil {
			b.base.log.Debug("failed to unmarshal RouteDiscovery", "error", err)
			return
		}
		if data.RequestId != 0 {
			// This is a traceroute response travelling back to the originator.
			// Build the return route before surfacing it to consumers.
			b.handleTracerouteResponse(reqCtx, rd)
			b.base.emitEvent(&event.TracerouteReceived{
				Event:            evt,
				RouteDiscovery:   rd,
				IsRequest:        false,
				OriginalPacketID: data.RequestId,
			})
		} else {
			// This is an incoming traceroute request. The bridge answers on
			// behalf of the managed destination; it is not surfaced as an event.
			b.handleTracerouteRequest(reqCtx, rd)
		}

	case pb.PortNum_ROUTING_APP:
		routing := &pb.Routing{}
		if err := proto.Unmarshal(data.Payload, routing); err != nil {
			b.base.log.Debug("failed to unmarshal Routing", "error", err)
			return
		}
		b.base.emitEvent(&event.RoutingReceived{
			Event:            evt,
			ErrorReason:      routing.GetErrorReason(),
			OriginalPacketID: data.RequestId,
		})

	default:
		b.base.emitEvent(&event.PacketReceived{Event: evt})
	}
}

// respondNodeInfoForManaged answers a NodeInfo WantResponse request. The bridge
// always replies as itself. If the request was a direct message to a specific
// managed node, that node also replies. Each reply is throttled independently.
func (b *BridgeNode) respondNodeInfoForManaged(evt event.Event) {
	requester := evt.From.Uint32()
	requestID := evt.PacketID

	// Respond as the bridge itself.
	if b.base.throttle.canRespond(b.cfg.NodeID, pb.PortNum_NODEINFO_APP) {
		b.sendNodeInfoResponse(b.cfg.NodeID, requester, requestID)
	}

	// Respond as the addressed managed node on a direct message.
	to := evt.To
	if !to.IsBroadcast() && to != b.cfg.NodeID && b.cfg.IsManagedNode(to) {
		if b.base.throttle.canRespond(to, pb.PortNum_NODEINFO_APP) {
			b.sendNodeInfoResponse(to, requester, requestID)
		}
	}
}

// sendNodeInfoResponse sends a NodeInfo response from the specified identity.
func (b *BridgeNode) sendNodeInfoResponse(asNode core.NodeID, to uint32, requestID uint32) {
	user := b.buildUserFor(asNode)
	if user == nil {
		return
	}

	userBytes, err := proto.Marshal(user)
	if err != nil {
		b.base.log.Error("failed to marshal NodeInfo", "error", err)
		return
	}

	pkt := &pb.MeshPacket{
		From: asNode.Uint32(),
		To:   to,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum:   pb.PortNum_NODEINFO_APP,
				Payload:   userBytes,
				RequestId: requestID,
			},
		},
	}
	b.adjustHopForRelay(pkt, asNode)
	if err := b.base.sendPacket(context.Background(), pkt, ""); err != nil {
		b.base.log.Error("failed to send NodeInfo response", "as", asNode, "to", core.NodeID(to), "error", err)
	} else {
		b.base.log.Debug("sent NodeInfo response", "as", asNode, "to", core.NodeID(to))
	}
}

// buildUserFor constructs the NodeInfo User for a managed identity. The bridge
// itself reports CLIENT_BASE and is flagged unmessagable; other managed nodes
// report CLIENT_MUTE. Names and public key come from the NodeInfoForNode
// callback for non-bridge identities. Returns nil if no info is available.
func (b *BridgeNode) buildUserFor(asNode core.NodeID) *pb.User {
	var longName, shortName string
	var pubKey []byte

	if asNode == b.cfg.NodeID {
		longName = b.cfg.LongName
		shortName = b.cfg.ShortName
		// Bridge's own public key is not exposed via config; omit.
	} else if b.cfg.NodeInfoForNode != nil {
		var ok bool
		longName, shortName, pubKey, ok = b.cfg.NodeInfoForNode(asNode)
		if !ok {
			return nil
		}
	} else {
		return nil
	}

	user := &pb.User{
		Id:        asNode.String(),
		LongName:  longName,
		ShortName: shortName,
		HwModel:   b.cfg.HwModel,
		Macaddr:   asNode.MacBytes(),
		PublicKey: pubKey,
		Role:      pb.Config_DeviceConfig_CLIENT_MUTE,
	}
	if asNode == b.cfg.NodeID {
		user.Role = pb.Config_DeviceConfig_CLIENT_BASE
		t := true
		user.IsUnmessagable = &t
	}
	return user
}

// SendTextAs sends a text message from a managed node and returns the packet ID.
func (b *BridgeNode) SendTextAs(ctx context.Context, from, to core.NodeID, message string, opts ...SendOption) (uint32, error) {
	o := applySendOptions(opts)
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum: pb.PortNum_TEXT_MESSAGE_APP,
		payload: []byte(message),
		enc:     encModeFor(o.usePKI),
		channel: o.channel,
		replyID: o.replyID,
		emoji:   o.emoji,
		wantAck: o.wantAck,
	})
}

// SendDataAs sends a data payload from a managed node. If usePKI is true and
// keys are available, the packet is PKI-encrypted. Otherwise falls back to PSK.
func (b *BridgeNode) SendDataAs(ctx context.Context, from, to core.NodeID, data *pb.Data, usePKI bool) error {
	if !b.cfg.IsManagedNode(from) {
		return fmt.Errorf("node %s is not managed by this bridge", from)
	}

	if usePKI {
		err := b.sendPKIPacketAs(ctx, from, to, data)
		if err == nil {
			return nil
		}
		b.base.log.Debug("PKI send failed, falling back to PSK", "from", from, "to", to, "error", err)
	}

	pkt := &pb.MeshPacket{
		From: from.Uint32(),
		To:   to.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: data,
		},
	}
	b.adjustHopForRelay(pkt, from)
	return b.base.sendPacket(ctx, pkt, "")
}

// SendAckAs sends a routing ACK from a managed node.
func (b *BridgeNode) SendAckAs(ctx context.Context, from, to core.NodeID, packetID uint32) error {
	if !b.cfg.IsManagedNode(from) {
		return fmt.Errorf("node %s is not managed by this bridge", from)
	}

	routing := &pb.Routing{
		Variant: &pb.Routing_ErrorReason{
			ErrorReason: pb.Routing_NONE,
		},
	}
	routingBytes, err := proto.Marshal(routing)
	if err != nil {
		return fmt.Errorf("marshalling routing: %w", err)
	}
	pkt := &pb.MeshPacket{
		From:     from.Uint32(),
		To:       to.Uint32(),
		Priority: pb.MeshPacket_ACK,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum:   pb.PortNum_ROUTING_APP,
				Payload:   routingBytes,
				RequestId: packetID,
			},
		},
	}
	b.adjustHopForRelay(pkt, from)
	return b.base.sendPacket(ctx, pkt, "")
}

// SendNodeInfoAs sends a NodeInfo packet from a managed node. Pass
// WithWantResponse to request the recipient's NodeInfo in return (used to
// discover unknown nodes). Returns the generated packet ID.
func (b *BridgeNode) SendNodeInfoAs(ctx context.Context, from, to core.NodeID, opts ...SendOption) (uint32, error) {
	user := b.buildUserFor(from)
	if user == nil {
		return 0, fmt.Errorf("no NodeInfo available for %s", from)
	}
	userBytes, err := proto.Marshal(user)
	if err != nil {
		return 0, fmt.Errorf("marshalling user: %w", err)
	}

	o := applySendOptions(opts)
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum:      pb.PortNum_NODEINFO_APP,
		payload:      userBytes,
		enc:          encModeFor(o.usePKI),
		channel:      o.channel,
		wantResponse: o.wantResponse,
	})
}

// sendPKIPacketAs sends a PKI-encrypted packet from a managed node.
func (b *BridgeNode) sendPKIPacketAs(ctx context.Context, from, to core.NodeID, data *pb.Data) error {
	if b.cfg.PrivateKeyForNode == nil {
		return fmt.Errorf("PrivateKeyForNode not configured")
	}
	privKey := b.cfg.PrivateKeyForNode(from)
	if privKey == nil {
		return fmt.Errorf("no private key for %s", from)
	}

	if b.cfg.PublicKeyForNode == nil {
		return fmt.Errorf("PublicKeyForNode not configured")
	}
	pubKey := b.cfg.PublicKeyForNode(to)
	if pubKey == nil {
		return fmt.Errorf("no public key for recipient %s", to)
	}

	plaintext, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling data: %w", err)
	}

	packetID := b.base.packetIDs.next()
	encrypted, err := crypto.EncryptCurve25519(plaintext, privKey, pubKey, packetID, from.Uint32())
	if err != nil {
		return fmt.Errorf("PKI encryption: %w", err)
	}

	pkt := &pb.MeshPacket{
		Id:           packetID,
		From:         from.Uint32(),
		To:           to.Uint32(),
		Channel:      0,
		PkiEncrypted: true,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: encrypted,
		},
	}
	b.base.applyPacketDefaults(pkt)
	b.adjustHopForRelay(pkt, from)

	b.base.sendMu.Lock()
	defer b.base.sendMu.Unlock()
	if !b.base.lastSend.IsZero() {
		if elapsed := time.Since(b.base.lastSend); elapsed < sendDelay {
			time.Sleep(sendDelay - elapsed)
		}
	}
	b.base.lastSend = time.Now()

	return b.base.transport.SendPacket(b.base.primaryChannel, pkt)
}

// adjustHopForRelay adds +1 to HopStart when the sending identity differs
// from the bridge's own NodeID. This compensates for the bridge acting as
// an extra relay hop between the virtual node and the mesh.
func (b *BridgeNode) adjustHopForRelay(pkt *pb.MeshPacket, from core.NodeID) {
	if from != b.cfg.NodeID {
		// Ensure defaults are applied first so HopStart is set
		if pkt.HopLimit == 0 {
			pkt.HopLimit = b.base.hopLimit
		}
		if pkt.HopStart == 0 {
			pkt.HopStart = pkt.HopLimit
		}
		pkt.HopStart++
		pkt.HopLimit++
		// Clamp to max
		if pkt.HopStart > core.MaxHops {
			pkt.HopStart = core.MaxHops
		}
		if pkt.HopLimit > core.MaxHops {
			pkt.HopLimit = core.MaxHops
		}
	}
}
