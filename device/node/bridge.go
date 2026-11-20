package node

import (
	"context"
	"errors"
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

	// ManualAcks stops the bridge acking want_ack packets addressed to its
	// identities, for consumers that ack with SendAckAs themselves. Naks for
	// packets the bridge could not decode are still sent, since only the bridge
	// sees those.
	ManualAcks bool

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
	// Used for both PKI encryption (managed→remote) and decryption (remote→managed),
	// and for the bridge's own key when it advertises NodeInfo.
	PublicKeyForNode func(core.NodeID) []byte

	// SignaturePolicy controls how received packets are authenticated. The zero
	// value is COMPATIBLE, the firmware wire default: unsigned packets are
	// accepted, malformed or invalid signatures are dropped. BALANCED also refuses
	// unsigned identity changes from nodes known to sign, and STRICT drops most
	// unsigned packets. When PrivateKeyForNode supplies a key, outbound packets are
	// signed under every policy, choosing which packets the way firmware's
	// BALANCED does.
	SignaturePolicy pb.Config_SecurityConfig_PacketSignaturePolicy

	// Licensed marks the bridge's identities as licensed (amateur radio)
	// operators. Licensed traffic stays plaintext, so firmware signs unicasts as
	// well as broadcasts and expects the same of peers. Applies to every managed
	// node; firmware has no per-identity notion of this either.
	Licensed bool

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
			transport: cfg.Transport,
			channels:  channels,
			dedup:     dedupe.NewDeduplicator(2 * time.Hour),
			throttle:  newRequestThrottle(),
			log:       logger,
			nodeID:    cfg.NodeID,
			okToMQTT:  cfg.OkToMQTT,
			hopLimit:  cfg.DefaultHopLimit,
			primary:   core.ChannelFromSettings(cfg.Channels.Settings[0]),
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
	b.base.db = b.db
	b.base.signaturePolicy = cfg.SignaturePolicy
	b.base.licensed = cfg.Licensed
	b.base.privateKeyFor = func(id core.NodeID) []byte {
		if cfg.PrivateKeyForNode == nil {
			return nil
		}
		return cfg.PrivateKeyForNode(id)
	}
	// The consumer's own key store is authoritative; a key learned from a NodeInfo
	// is the fallback, pinned by pinIdentity once held.
	b.base.publicKeyFor = func(id core.NodeID) []byte {
		if cfg.PublicKeyForNode != nil {
			if key := cfg.PublicKeyForNode(id); key != nil {
				return key
			}
		}
		if info := b.db.Get(id.Uint32()); info != nil && info.User != nil {
			return info.User.PublicKey
		}
		return nil
	}

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

// SetNodeChannel records that nodeID was last heard on this channel, as if its
// NodeInfo had arrived there, so a consumer with persistent storage can restore
// unicast routing after a restart. The channel is matched by name and key
// against the registered channels and must already be registered; reports false
// otherwise. Marks the node as heard now.
func (b *BridgeNode) SetNodeChannel(nodeID core.NodeID, ch core.ChannelDef) bool {
	if ch == nil {
		return false
	}
	registered, ok := b.base.channels.LookupPair(ch.GetName(), ch.GetKeyBytes())
	if !ok {
		return false
	}
	b.db.Update(nodeID.Uint32(), func(*pb.NodeInfo) {})
	b.db.SetChannel(nodeID.Uint32(), registered)
	return true
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

	// 2. Self-echo filter: drop packets where From is the bridge or a managed node
	from := core.NodeID(pkt.Packet.From)
	if from == b.cfg.NodeID || b.cfg.IsManagedNode(from) {
		b.base.log.Debug("dropping self-echo from managed node", "from", from)
		return
	}

	// 3. If already decoded, process directly
	if decoded := pkt.Packet.GetDecoded(); decoded != nil {
		ch, channelName := b.base.decodedChannel(pkt)
		b.processDecoded(pkt, decoded, ch, channelName, false, 0)
		return
	}

	// 4. Try PKI decryption if addressed to a managed node
	to := core.NodeID(pkt.Packet.To)
	if b.shouldTryPKI(pkt.Packet) {
		data, err := b.tryDecryptPKI(pkt.Packet)
		if err == nil && data != nil {
			b.processDecoded(pkt, data, nil, "PKI", true, to)
			return
		}
		b.base.log.Debug("PKI decryption failed, falling back to PSK", "error", err)
	}

	// 5. Try PSK decryption with every registered channel matching the hash. The
	// one-byte hash collides, so like firmware we try each and keep the first
	// that yields a plausible Data; a wrong key that happens to decode reports
	// UNKNOWN_APP.
	candidates := b.base.channels.LookupAll(pkt.Packet.Channel)
	if len(candidates) == 0 {
		b.base.log.Debug("unknown channel hash", "hash", pkt.Packet.Channel)
		b.nakUndecodable(pkt.Packet)
		return
	}
	for _, ch := range candidates {
		data, err := crypto.TryDecode(pkt.Packet, ch.GetKeyBytes())
		if err != nil || data.Portnum == pb.PortNum_UNKNOWN_APP {
			continue
		}
		if b.base.isLegacyDM(pkt.Packet, data) {
			b.base.log.Warn("rejecting channel-encrypted DM", "from", core.NodeID(pkt.Packet.From), "packetID", pkt.Packet.Id)
			b.nakUndecodable(pkt.Packet)
			return
		}
		b.processDecoded(pkt, data, ch, ch.GetName(), false, 0)
		return
	}
	b.base.log.Debug("PSK decryption failed on every matching channel", "hash", pkt.Packet.Channel)
	b.nakUndecodable(pkt.Packet)
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
func (b *BridgeNode) processDecoded(pkt transport.NetworkPacket, data *pb.Data, ch core.ChannelDef, channelName string, isPKI bool, managedTo core.NodeID) {
	signed, ok := b.base.checkSignaturePolicy(pkt.Packet, data, isPKI)
	if !ok {
		b.base.log.Debug("dropping packet under signature policy",
			"from", core.NodeID(pkt.Packet.From), "packetID", pkt.Packet.Id)
		return
	}
	var channelKey *string
	if ch != nil {
		k := ch.GetKeyString()
		channelKey = &k
	}
	via := gatewayNode(pkt)
	evt := event.Event{
		ChannelName:   channelName,
		Channel:       ch,
		ChannelKey:    channelKey,
		From:          core.NodeID(pkt.Packet.From),
		To:            core.NodeID(pkt.Packet.To),
		Via:           via,
		Timestamp:     time.Now(),
		PacketID:      pkt.Packet.Id,
		Portnum:       data.Portnum,
		IsPKI:         isPKI,
		IsSigned:      signed,
		RawData:       data,
		ManagedNodeID: managedTo,
		WantAck:       pkt.Packet.WantAck,
		WantResponse:  data.WantResponse,
		IsAutomation:  data.GetBitfield()&bitfieldIsAutomation != 0,
		IsNeighbor: pkt.Source != transport.PacketSourceMQTT &&
			pkt.Packet.HopStart == pkt.Packet.HopLimit && !pkt.Packet.ViaMqtt,
	}
	if pkt.Packet.GetRxTime() > 0 {
		evt.Timestamp = time.Unix(int64(pkt.Packet.GetRxTime()), 0)
	}

	// reqCtx carries the raw-packet fields the request responders need.
	reqCtx := eventContext{
		From:        evt.From,
		To:          evt.To,
		Via:         via,
		PacketID:    evt.PacketID,
		ChannelName: channelName,
		Channel:     ch,
		WantAck:     pkt.Packet.WantAck,
		HopStart:    pkt.Packet.HopStart,
		HopLimit:    pkt.Packet.HopLimit,
		RxSnr:       pkt.Packet.RxSnr,
	}

	from := pkt.Packet.From

	// Firmware acks after the modules have run, and not at all when one of them
	// already replied.
	replied := false
	if b.isOurs(evt.To) && !b.cfg.ManualAcks {
		defer func() {
			if !replied {
				b.sendRouting(b.base.ackFor(pkt.Packet, data), ch)
			}
		}()
	}

	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			b.base.log.Debug("failed to unmarshal NodeInfo", "error", err)
			return
		}
		if b.base.pinIdentity(from, user, evt.IsSigned) {
			b.db.Update(from, func(info *pb.NodeInfo) { info.User = user })
			// Remember which of our channels this node is reachable on.
			if ch != nil {
				b.db.SetChannel(from, ch)
			}
			b.base.emitEvent(&event.NodeInfoUpdated{Event: evt, User: user})
		}

		// Auto-respond to NodeInfo WantResponse on behalf of managed nodes
		if data.WantResponse {
			replied = b.respondNodeInfoForManaged(evt)
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
			replied = b.respondTelemetry(reqCtx, tel)
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

	case pb.PortNum_MESH_BEACON_APP:
		beacon := &pb.MeshBeacon{}
		if err := proto.Unmarshal(data.Payload, beacon); err != nil {
			b.base.log.Debug("failed to unmarshal MeshBeacon", "error", err)
			return
		}
		hasOffer := core.MeshBeaconHasOffer(beacon)
		if beacon.Message == "" && !hasOffer {
			return // nothing to act on, and firmware does not either
		}
		b.base.emitEvent(&event.MeshBeaconReceived{Event: evt, Beacon: beacon, HasOffer: hasOffer})

	case pb.PortNum_NEIGHBORINFO_APP:
		ni := &pb.NeighborInfo{}
		if err := proto.Unmarshal(data.Payload, ni); err != nil {
			b.base.log.Debug("failed to unmarshal NeighborInfo", "error", err)
			return
		}
		b.base.emitEvent(&event.NeighborInfoReceived{Event: evt, NeighborInfo: ni})

		// Auto-respond to neighbor info requests addressed to a managed node.
		if data.WantResponse && !evt.To.IsBroadcast() {
			replied = b.respondNeighborInfo(reqCtx, ni)
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
			replied = b.handleTracerouteRequest(reqCtx, rd)
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
		// The peer could not decrypt a PKI packet from this identity for lack of
		// its key, so send it the identity's NodeInfo, which carries it.
		if routing.GetErrorReason() == pb.Routing_PKI_UNKNOWN_PUBKEY && b.isOurs(evt.To) &&
			b.base.throttle.canRespond(evt.To, pb.PortNum_NODEINFO_APP) {
			b.sendNodeInfoResponse(evt.To, from, 0)
		}

	default:
		b.base.emitEvent(&event.PacketReceived{Event: evt})
	}
}

// respondNodeInfoForManaged answers a NodeInfo WantResponse request the way
// firmware's MeshModule would if each identity were its own node: only the
// addressed identity replies, and only the bridge itself answers a broadcast.
// Requests we overhear between other nodes get no reply. It reports whether a
// reply went out.
func (b *BridgeNode) respondNodeInfoForManaged(evt event.Event) bool {
	responder := evt.To
	if responder.IsBroadcast() {
		responder = b.cfg.NodeID
	} else if !b.isOurs(responder) {
		return false
	}
	return b.base.throttle.canRespond(responder, pb.PortNum_NODEINFO_APP) &&
		b.sendNodeInfoResponse(responder, evt.From.Uint32(), evt.PacketID)
}

// isOurs reports whether id is the bridge itself or one of its managed nodes.
func (b *BridgeNode) isOurs(id core.NodeID) bool {
	return id == b.cfg.NodeID || b.cfg.IsManagedNode(id)
}

// sendRouting sends an ack or nak built by ackFor or nakFor from the identity
// the answered packet was addressed to, on its channel, or the primary for PKI
// and undecodable packets.
func (b *BridgeNode) sendRouting(pkt *pb.MeshPacket, ch core.ChannelDef) {
	if pkt == nil {
		return
	}
	if ch == nil {
		ch = b.base.primary
	}
	b.adjustHopForRelay(pkt, core.NodeID(pkt.From))
	if err := b.base.sendPacketOn(context.Background(), pkt, ch, false); err != nil {
		b.base.log.Error("failed to send routing response", "as", core.NodeID(pkt.From), "to", core.NodeID(pkt.To), "error", err)
	}
}

// nakUndecodable naks a want_ack packet addressed to one of our identities that
// we could not decode.
func (b *BridgeNode) nakUndecodable(pkt *pb.MeshPacket) {
	if b.isOurs(core.NodeID(pkt.To)) {
		b.sendRouting(b.base.nakFor(pkt), nil)
	}
}

// sendNodeInfoResponse sends a NodeInfo response from the specified identity,
// reporting whether it went out.
func (b *BridgeNode) sendNodeInfoResponse(asNode core.NodeID, to uint32, requestID uint32) bool {
	user := b.buildUserFor(asNode)
	if user == nil {
		return false
	}
	if err := checkNodeInfoIdentity(asNode, user); err != nil {
		b.base.log.Error("refusing NodeInfo response", "as", asNode, "error", err)
		return false
	}

	userBytes, err := proto.Marshal(user)
	if err != nil {
		b.base.log.Error("failed to marshal NodeInfo", "error", err)
		return false
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
		return false
	}
	b.base.log.Debug("sent NodeInfo response", "as", asNode, "to", core.NodeID(to))
	return true
}

// ErrIdentityMismatch reports a NodeInfo whose public key does not derive its
// node ID. Firmware 2.8 rejects such a NodeInfo on first contact once it is
// signed, so sending one only makes the identity invisible to new peers.
var ErrIdentityMismatch = errors.New("node ID is not derived from the public key")

// checkNodeInfoIdentity enforces the 2.8 identity binding on a NodeInfo we are
// about to send. A NodeInfo without a key is left alone.
func checkNodeInfoIdentity(asNode core.NodeID, user *pb.User) error {
	if len(user.PublicKey) == 0 {
		return nil
	}
	if !asNode.MatchesPublicKey(user.PublicKey) {
		return fmt.Errorf("%w: %s", ErrIdentityMismatch, asNode)
	}
	return nil
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
		if b.cfg.PublicKeyForNode != nil {
			pubKey = b.cfg.PublicKeyForNode(asNode)
		}
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
		channel: o.channel, channelDef: o.channelDef,
		replyID:    o.replyID,
		emoji:      o.emoji,
		wantAck:    o.wantAck,
		automation: o.automation,
	})
}

// SendDataAs sends a data payload from a managed node. Unicasts are
// PKI-encrypted whenever firmware would (see usesPKI), and fail with
// ErrNoPublicKey when the recipient's key is unknown. requirePKI also fails a
// send that would otherwise go out on a channel key.
func (b *BridgeNode) SendDataAs(ctx context.Context, from, to core.NodeID, data *pb.Data, requirePKI bool) error {
	if !b.cfg.IsManagedNode(from) {
		return fmt.Errorf("node %s is not managed by this bridge", from)
	}
	pkt := &pb.MeshPacket{
		From:           from.Uint32(),
		To:             to.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}
	b.adjustHopForRelay(pkt, from)
	return b.base.sendPacketWith(ctx, pkt, sendOptions{usePKI: requirePKI})
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
// discover unknown nodes). Returns the generated packet ID, or
// ErrIdentityMismatch if the identity's key does not derive its node ID.
func (b *BridgeNode) SendNodeInfoAs(ctx context.Context, from, to core.NodeID, opts ...SendOption) (uint32, error) {
	user := b.buildUserFor(from)
	if user == nil {
		return 0, fmt.Errorf("no NodeInfo available for %s", from)
	}
	if err := checkNodeInfoIdentity(from, user); err != nil {
		return 0, err
	}
	userBytes, err := proto.Marshal(user)
	if err != nil {
		return 0, fmt.Errorf("marshalling user: %w", err)
	}

	o := applySendOptions(opts)
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum: pb.PortNum_NODEINFO_APP,
		payload: userBytes,
		enc:     encModeFor(o.usePKI),
		channel: o.channel, channelDef: o.channelDef,
		wantResponse: o.wantResponse,
		automation:   o.automation,
	})
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
