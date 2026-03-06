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

// Run starts the transport and incoming packet pipeline. It blocks until ctx is cancelled.
func (b *BridgeNode) Run(ctx context.Context) error {
	b.base.transport.SetPacketHandler(b.handleIncomingPacket)

	// Subscribe to configured channels
	for _, ch := range b.cfg.Channels.Settings {
		b.base.log.Debug("subscribing to channel", "channel", ch.Name)
		b.base.transport.AddChannel(ch.Name)
	}

	if err := b.base.transport.Start(ctx); err != nil {
		return fmt.Errorf("starting transport: %w", err)
	}

	<-ctx.Done()
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
		b.processDecoded(pkt, decoded, channelName, false, 0)
		return
	}

	// 4. Try PKI decryption if addressed to a managed node
	to := core.NodeID(pkt.Packet.To)
	if b.shouldTryPKI(pkt.Packet) {
		data, err := b.tryDecryptPKI(pkt.Packet)
		if err == nil && data != nil {
			b.processDecoded(pkt, data, "PKI", true, to)
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

	b.processDecoded(pkt, data, ch.GetName(), false, 0)
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
// managedTo is the managed node this packet was addressed to (for PKI unicast),
// or 0 for PSK/broadcast packets.
func (b *BridgeNode) processDecoded(pkt transport.NetworkPacket, data *pb.Data, channelName string, isPKI bool, managedTo core.NodeID) {
	evt := event.Event{
		ChannelName:   channelName,
		From:          core.NodeID(pkt.Packet.From),
		To:            core.NodeID(pkt.Packet.To),
		Timestamp:     time.Now(),
		PacketID:      pkt.Packet.Id,
		Portnum:       data.Portnum,
		IsPKI:         isPKI,
		RawData:       data,
		ManagedNodeID: managedTo,
	}
	if pkt.Packet.RxTime > 0 {
		evt.Timestamp = time.Unix(int64(pkt.Packet.RxTime), 0)
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
			b.respondNodeInfoForManaged(from, pkt.Packet.Id)
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
		isRequest := data.WantResponse
		b.base.emitEvent(&event.TracerouteReceived{Event: evt, RouteDiscovery: rd, IsRequest: isRequest})

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

// respondNodeInfoForManaged sends NodeInfo responses on behalf of all managed
// nodes that pass the throttle check. This handles broadcast WantResponse
// requests where all managed nodes should reply.
func (b *BridgeNode) respondNodeInfoForManaged(requester uint32, requestID uint32) {
	if b.cfg.NodeInfoForNode == nil {
		return
	}

	// Respond as the bridge itself
	if b.base.throttle.canRespond(core.NodeID(requester), pb.PortNum_NODEINFO_APP) {
		b.sendNodeInfoResponse(b.cfg.NodeID, requester, requestID)
	}
}

// sendNodeInfoResponse sends a NodeInfo response from the specified identity.
func (b *BridgeNode) sendNodeInfoResponse(asNode core.NodeID, to uint32, requestID uint32) {
	var longName, shortName string
	var pubKey []byte

	if asNode == b.cfg.NodeID {
		longName = b.cfg.LongName
		shortName = b.cfg.ShortName
		// Bridge's own public key not exposed via config; omit
	} else if b.cfg.NodeInfoForNode != nil {
		var ok bool
		longName, shortName, pubKey, ok = b.cfg.NodeInfoForNode(asNode)
		if !ok {
			return
		}
	} else {
		return
	}

	user := &pb.User{
		Id:        asNode.String(),
		LongName:  longName,
		ShortName: shortName,
		HwModel:   b.cfg.HwModel,
		PublicKey: pubKey,
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
	if err := b.base.sendPacket(context.Background(), pkt, ""); err != nil {
		b.base.log.Error("failed to send NodeInfo response", "as", asNode, "to", core.NodeID(to), "error", err)
	} else {
		b.base.log.Debug("sent NodeInfo response", "as", asNode, "to", core.NodeID(to))
	}
}

// SendTextAs sends a text message from a managed node.
func (b *BridgeNode) SendTextAs(ctx context.Context, from, to core.NodeID, message string, opts ...SendOption) error {
	if len(message) > core.MaxDataPayload {
		return fmt.Errorf("message too large: %d bytes exceeds max %d", len(message), core.MaxDataPayload)
	}
	if !b.cfg.IsManagedNode(from) {
		return fmt.Errorf("node %s is not managed by this bridge", from)
	}

	o := applySendOptions(opts)

	data := &pb.Data{
		Portnum: pb.PortNum_TEXT_MESSAGE_APP,
		Payload: []byte(message),
		ReplyId: o.replyID,
		Emoji:   o.emoji,
	}

	if o.usePKI {
		return b.SendDataAs(ctx, from, to, data, true)
	}

	pkt := &pb.MeshPacket{
		From:           from.Uint32(),
		To:             to.Uint32(),
		WantAck:        o.wantAck,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}
	b.adjustHopForRelay(pkt, from)
	return b.base.sendPacket(ctx, pkt, o.channel)
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

// SendNodeInfoAs broadcasts a NodeInfo packet from a managed node.
func (b *BridgeNode) SendNodeInfoAs(ctx context.Context, from core.NodeID, to core.NodeID) error {
	if !b.cfg.IsManagedNode(from) {
		return fmt.Errorf("node %s is not managed by this bridge", from)
	}
	if b.cfg.NodeInfoForNode == nil {
		return fmt.Errorf("NodeInfoForNode callback not configured")
	}

	longName, shortName, pubKey, ok := b.cfg.NodeInfoForNode(from)
	if !ok {
		return fmt.Errorf("no NodeInfo available for %s", from)
	}

	user := &pb.User{
		Id:        from.String(),
		LongName:  longName,
		ShortName: shortName,
		HwModel:   b.cfg.HwModel,
		PublicKey: pubKey,
	}
	userBytes, err := proto.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshalling user: %w", err)
	}

	pkt := &pb.MeshPacket{
		From:     from.Uint32(),
		To:       to.Uint32(),
		Priority: pb.MeshPacket_BACKGROUND,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_NODEINFO_APP,
				Payload: userBytes,
			},
		},
	}
	b.adjustHopForRelay(pkt, from)
	return b.base.sendPacket(ctx, pkt, "")
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
