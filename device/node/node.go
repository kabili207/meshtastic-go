// Package node provides the glue that wires together the device components
// (nodedb, broadcast, clientapi) over a raw transport to form a complete
// emulated Meshtastic node.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
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

	// NodeID is this node's identity. When PublicKey is set, NodeID may be left
	// zero and is derived from the key the way firmware 2.8 does; if both are set
	// they must agree, or New returns ErrIdentityMismatch.
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

	// Position coordinates. Like firmware, positions are only sent (broadcast or
	// in reply) on the lowest-indexed channel whose module_settings set a non-zero
	// position_precision, coarsened to it, and to 15 bits on a channel with a
	// public key.
	PositionLatitudeI  int32
	PositionLongitudeI int32
	PositionAltitude   int32

	// TCPListenAddr for the client API TCP listener. Empty disables.
	TCPListenAddr string

	// OnConfigChange decides on settings changes a connected app sends. Accepted
	// changes are shown to apps from then on, but applying them to the running
	// node, or persisting them, is the handler's job. Nil refuses every change.
	OnConfigChange clientapi.ConfigChangeHandler

	// PrivateKey is the X25519 private key for this node. If nil, PKI is disabled.
	PrivateKey []byte

	// PublicKey is the X25519 public key for this node. If nil, PKI is disabled.
	PublicKey []byte

	// SignaturePolicy controls how received packets are authenticated. The zero
	// value is COMPATIBLE, the firmware wire default: unsigned packets are
	// accepted, malformed or invalid signatures are dropped. BALANCED also refuses
	// unsigned identity changes from nodes known to sign, and STRICT drops most
	// unsigned packets. When PrivateKey is set, outbound packets are signed under
	// every policy, choosing which packets the way firmware's BALANCED does.
	SignaturePolicy pb.Config_SecurityConfig_PacketSignaturePolicy

	// Licensed marks this node as a licensed (amateur radio) operator. Licensed
	// traffic stays plaintext, so firmware signs unicasts as well as broadcasts
	// and expects the same of peers. It is advertised in NodeInfo, and firmware
	// drops NodeInfo whose licensed bit differs from its own.
	Licensed bool

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
	if len(c.PublicKey) > 0 && len(c.PublicKey) != core.PublicKeySize {
		return fmt.Errorf("PublicKey must be %d bytes, got %d", core.PublicKeySize, len(c.PublicKey))
	}
	if c.NodeID == 0 && len(c.PublicKey) == core.PublicKeySize {
		c.NodeID, _ = core.NodeIDFromPublicKey(c.PublicKey) // length checked above
	}
	if c.NodeID == 0 {
		return fmt.Errorf("NodeID is required")
	}
	// A NodeInfo whose key does not derive its ID is rejected by every 2.8 peer on
	// first contact, so a mismatch here would make the node permanently unverifiable.
	if len(c.PublicKey) > 0 && !c.NodeID.MatchesPublicKey(c.PublicKey) {
		return fmt.Errorf("%w: %s", ErrIdentityMismatch, c.NodeID)
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
		c.DefaultHopLimit = core.DefaultHopLimit
	}
	if c.DefaultHopLimit > core.MaxHops {
		c.DefaultHopLimit = core.MaxHops
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

	// channelDefs is the configured channel set, resolved. Clients name channels
	// by their index in it.
	channelDefs []*core.Channel

	positionOffWarning sync.Once
}

// New creates a Node with the given configuration. It validates the config,
// constructs all sub-components, and wires their callbacks.
func New(cfg Config) (*Node, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	logger := cfg.Logger.WithGroup("node").With("node", cfg.NodeID.String())

	// Build channel registry from configured channels
	defs := core.ChannelsFromSet(cfg.Channels)
	channels := core.NewChannelRegistry()
	for _, ch := range defs {
		if ch != nil {
			channels.Register(ch)
		}
	}

	n := &Node{
		base: baseNode{
			transport: cfg.Transport,
			channels:  channels,
			dedup:     dedupe.NewDeduplicator(2 * time.Hour),
			throttle:  newRequestThrottle(),
			log:       logger,
			nodeID:    cfg.NodeID,
			okToMQTT:  cfg.OkToMQTT,
			hopLimit:  cfg.DefaultHopLimit,
			primary:   defs[0],
		},
		cfg:         cfg,
		channelDefs: defs,
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
	n.base.db = n.db
	n.base.signaturePolicy = cfg.SignaturePolicy
	n.base.licensed = cfg.Licensed
	n.base.privateKeyFor = func(id core.NodeID) []byte {
		if id == cfg.NodeID {
			return cfg.PrivateKey
		}
		return nil
	}
	n.base.publicKeyFor = n.lookupPublicKey

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
		HwModel:               cfg.HwModel,
		PublicKey:             cfg.PublicKey,
		Channels:              cfg.Channels,
		LoRa:                  loraConfigFor(cfg.Channels, n.base.hopLimit),
		NodeInfoBroadcastSecs: uint32(cfg.BroadcastNodeInfoInterval.Seconds()),
		Nodes:                 n.db,
		NextPacketID:          n.base.packetIDs.next,
		OnOutboundPacket:      n.sendFromClient,
		OnConfigChange:        cfg.OnConfigChange,
		TCPListenAddr:         cfg.TCPListenAddr,
		Logger:                cfg.Logger,
	})

	return n, nil
}

// sendFromClient sends a packet a connected app handed us, the way firmware's
// MeshService::handleToRadio does: the app may not pick the sender or routing
// hints, its channel is an index into our channel table, and a pki_encrypted
// request means PKI or nothing.
func (n *Node) sendFromClient(ctx context.Context, pkt *pb.MeshPacket) pb.Routing_Error {
	pkt.From = n.cfg.NodeID.Uint32()
	pkt.NextHop = 0
	pkt.RelayNode = 0
	if pkt.Channel >= uint32(len(n.channelDefs)) || n.channelDefs[pkt.Channel] == nil {
		return pb.Routing_NO_CHANNEL
	}
	ch := n.channelDefs[pkt.Channel]
	pkt.Channel = 0
	err := n.base.sendPacketOn(ctx, pkt, ch, pkt.PkiEncrypted)
	if err != nil {
		n.base.log.Warn("failed to send packet from client", "to", core.NodeID(pkt.To), "error", err)
	}
	return routingErrorFor(err)
}

// routingErrorFor maps a send error to the Routing error firmware reports for it.
func routingErrorFor(err error) pb.Routing_Error {
	switch {
	case err == nil:
		return pb.Routing_NONE
	case errors.Is(err, ErrNoPublicKey):
		return pb.Routing_PKI_SEND_FAIL_PUBLIC_KEY
	case errors.Is(err, ErrPKIUnavailable):
		return pb.Routing_PKI_FAILED
	case errors.Is(err, ErrPacketTooLarge):
		return pb.Routing_TOO_LARGE
	}
	return pb.Routing_NO_INTERFACE
}

// deliverToClients hands a decoded packet to connected apps, as firmware's
// RoutingModule does: only broadcasts and packets for us, decoded, with the
// channel as an index into the table the handshake sent.
func (n *Node) deliverToClients(pkt *pb.MeshPacket, data *pb.Data, ch core.ChannelDef, isPKI bool) {
	to := core.NodeID(pkt.To)
	if !to.IsBroadcast() && to != n.cfg.NodeID {
		return
	}
	out := proto.Clone(pkt).(*pb.MeshPacket)
	out.PayloadVariant = &pb.MeshPacket_Decoded{Decoded: data}
	out.PkiEncrypted = isPKI
	out.Channel = 0
	for i, def := range n.channelDefs {
		if !isPKI && def != nil && core.SameChannel(def, ch) {
			out.Channel = uint32(i)
			break
		}
	}
	n.api.DispatchToClients(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Packet{Packet: out}})
}

// loraConfigFor is the LoRa config reported to clients: the channel set's own,
// as a channel URL carries it, or else firmware's defaults of LongFast with no
// region, which makes apps prompt for one.
func loraConfigFor(set *pb.ChannelSet, hopLimit uint32) *pb.Config_LoRaConfig {
	if cfg := set.GetLoraConfig(); cfg != nil {
		return cfg
	}
	return &pb.Config_LoRaConfig{
		UsePreset:   true,
		ModemPreset: pb.Config_LoRaConfig_LONG_FAST,
		HopLimit:    hopLimit,
		TxEnabled:   true,
	}
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
		Id:         n.cfg.NodeID.String(),
		LongName:   n.cfg.LongName,
		ShortName:  n.cfg.ShortName,
		HwModel:    n.cfg.HwModel,
		PublicKey:  n.cfg.PublicKey,
		IsLicensed: n.cfg.Licensed,
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
	posBytes, ch, ok := n.ourPosition()
	if !ok {
		return nil
	}
	n.base.log.Debug("broadcasting Position", "channel", ch.GetName())
	return n.base.sendPacketOn(ctx, &pb.MeshPacket{
		From:     n.cfg.NodeID.Uint32(),
		To:       core.BroadcastNodeID.Uint32(),
		Priority: pb.MeshPacket_BACKGROUND,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_POSITION_APP,
				Payload: posBytes,
			},
		},
	}, ch, false)
}

// ourPosition encodes our position for the mesh the way firmware's PositionModule
// does, for broadcasts and replies alike: on the lowest-indexed channel that
// allows any precision, coarsened to that channel's precision. Reports false when
// sharing is off on every channel or there are no coordinates to send.
func (n *Node) ourPosition() ([]byte, core.ChannelDef, bool) {
	if n.cfg.PositionLatitudeI == 0 && n.cfg.PositionLongitudeI == 0 {
		return nil, nil, false
	}
	table := make([]*pb.Channel, len(n.cfg.Channels.Settings))
	for i, settings := range n.cfg.Channels.Settings {
		table[i] = &pb.Channel{Index: int32(i), Role: pb.Channel_SECONDARY, Settings: settings}
	}
	table[0].Role = pb.Channel_PRIMARY

	idx, ok := core.FindPositionChannel(table)
	if !ok {
		n.positionOffWarning.Do(func() {
			n.base.log.Warn("position sharing is off on every channel; set module_settings.position_precision on one to send positions")
		})
		return nil, nil, false
	}
	pos := &pb.Position{
		LatitudeI:  proto.Int32(n.cfg.PositionLatitudeI),
		LongitudeI: proto.Int32(n.cfg.PositionLongitudeI),
		Altitude:   proto.Int32(n.cfg.PositionAltitude),
		Time:       uint32(time.Now().Unix()),
	}
	core.ApplyPositionPrecision(pos, core.PositionPrecisionForChannel(table, idx))
	posBytes, err := proto.Marshal(pos)
	if err != nil {
		n.base.log.Error("failed to marshal Position", "error", err)
		return nil, nil, false
	}
	return posBytes, core.ChannelsFromSet(n.cfg.Channels)[idx], true
}

// requestIsForUs reports whether a want_response request is ours to answer.
// Like firmware's MeshModule, we answer broadcasts and requests addressed to us,
// never requests we overhear between other nodes.
func (n *Node) requestIsForUs(pkt *pb.MeshPacket) bool {
	to := core.NodeID(pkt.To)
	return to.IsBroadcast() || to == n.cfg.NodeID
}

// respondNodeInfo sends our NodeInfo as a unicast response to a WantResponse
// request, reporting whether it went out.
func (n *Node) respondNodeInfo(to uint32, requestID uint32) bool {
	data := n.buildNodeInfoData(requestID)
	if data == nil {
		return false
	}
	pkt := &pb.MeshPacket{
		From:           n.cfg.NodeID.Uint32(),
		To:             to,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}
	if err := n.base.sendPacket(context.Background(), pkt, ""); err != nil {
		n.base.log.Error("failed to send NodeInfo response", "to", core.NodeID(to), "error", err)
		return false
	}
	n.base.log.Debug("sent NodeInfo response", "to", core.NodeID(to))
	return true
}

// respondPosition sends our Position as a unicast response to a WantResponse
// request, reporting whether it went out.
func (n *Node) respondPosition(to uint32, requestID uint32) bool {
	// Firmware replies on the position channel, not the one the request came in on,
	// and sends one reply per window across all requesters. Only a reply that can
	// actually go out uses up the window.
	posBytes, ch, ok := n.ourPosition()
	if !ok || !n.base.throttle.canRespond(n.cfg.NodeID, pb.PortNum_POSITION_APP) {
		return false
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
	if err := n.base.sendPacketOn(context.Background(), pkt, ch, false); err != nil {
		n.base.log.Error("failed to send Position response", "to", core.NodeID(to), "error", err)
		return false
	}
	n.base.log.Debug("sent Position response", "to", core.NodeID(to))
	return true
}

// sendRouting sends an ack or nak built by ackFor or nakFor, on the channel the
// packet it answers came in on, or the primary for PKI and undecodable packets.
func (n *Node) sendRouting(pkt *pb.MeshPacket, ch core.ChannelDef) {
	if pkt == nil {
		return
	}
	if ch == nil {
		ch = n.base.primary
	}
	if err := n.base.sendPacketOn(context.Background(), pkt, ch, false); err != nil {
		n.base.log.Error("failed to send routing response", "to", core.NodeID(pkt.To), "error", err)
	}
}

// nakUndecodable naks a want_ack packet addressed to us that we could not decode.
func (n *Node) nakUndecodable(pkt *pb.MeshPacket) {
	if core.NodeID(pkt.To) == n.cfg.NodeID {
		n.sendRouting(n.base.nakFor(pkt), nil)
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

	// 2. Drop packets claiming our own identity: an echo of our own send, or a spoof.
	// Firmware rejects these before they reach the router or any client.
	if core.NodeID(pkt.Packet.From) == n.cfg.NodeID {
		n.base.log.Debug("dropping packet claiming our own node ID", "packetID", pkt.Packet.Id)
		return
	}

	// 3. If already decoded, process directly
	if decoded := pkt.Packet.GetDecoded(); decoded != nil {
		ch, channelName := n.base.decodedChannel(pkt)
		n.processDecoded(pkt, decoded, ch, channelName, false)
		return
	}

	// 4. Try PKI decryption (channel==0, unicast to this node)
	if n.shouldTryPKI(pkt.Packet) {
		data, err := n.tryDecryptPKI(pkt.Packet)
		if err == nil && data != nil {
			n.processDecoded(pkt, data, nil, "PKI", true)
			return
		}
		n.base.log.Debug("PKI decryption failed, falling back to PSK", "error", err)
	}

	// 5. Try PSK decryption with every registered channel matching the hash. The
	// one-byte hash collides, so like firmware we try each and keep the first
	// that yields a plausible Data; a wrong key that happens to decode reports
	// UNKNOWN_APP.
	candidates := n.base.channels.LookupAll(pkt.Packet.Channel)
	if len(candidates) == 0 {
		n.base.log.Debug("unknown channel hash", "hash", pkt.Packet.Channel)
		n.nakUndecodable(pkt.Packet)
		return
	}
	for _, ch := range candidates {
		data, err := decodeOn(pkt.Packet, ch)
		if err != nil || data.Portnum == pb.PortNum_UNKNOWN_APP {
			continue
		}
		if n.base.isLegacyDM(pkt.Packet, data) {
			n.base.log.Warn("rejecting channel-encrypted DM", "from", core.NodeID(pkt.Packet.From), "packetID", pkt.Packet.Id)
			n.nakUndecodable(pkt.Packet)
			return
		}
		n.processDecoded(pkt, data, ch, ch.GetName(), false)
		return
	}
	n.base.log.Debug("PSK decryption failed on every matching channel", "hash", pkt.Packet.Channel)
	n.nakUndecodable(pkt.Packet)
}

// processDecoded handles a successfully decoded packet: updates the nodedb
// and emits typed events.
func (n *Node) processDecoded(pkt transport.NetworkPacket, data *pb.Data, ch core.ChannelDef, channelName string, isPKI bool) {
	signed, ok := n.base.checkSignaturePolicy(pkt.Packet, data, isPKI, core.ChannelIsAEAD(ch))
	if !ok {
		n.base.log.Debug("dropping packet under signature policy",
			"from", core.NodeID(pkt.Packet.From), "packetID", pkt.Packet.Id)
		return
	}
	evt := event.Event{
		ChannelName:  channelName,
		Channel:      ch,
		From:         core.NodeID(pkt.Packet.From),
		To:           core.NodeID(pkt.Packet.To),
		Timestamp:    time.Now(),
		PacketID:     pkt.Packet.Id,
		Portnum:      data.Portnum,
		IsPKI:        isPKI,
		IsSigned:     signed,
		RawData:      data,
		WantAck:      pkt.Packet.WantAck,
		WantResponse: data.WantResponse,
		IsAutomation: data.GetBitfield()&bitfieldIsAutomation != 0,
	}
	if pkt.Packet.GetRxTime() > 0 {
		evt.Timestamp = time.Unix(int64(pkt.Packet.GetRxTime()), 0)
	}

	from := pkt.Packet.From
	n.deliverToClients(pkt.Packet, data, ch, isPKI)

	// Firmware acks after the modules have run, and not at all when one of them
	// already replied.
	replied := false
	if evt.To == n.cfg.NodeID {
		defer func() {
			if !replied {
				n.sendRouting(n.base.ackFor(pkt.Packet, data), ch)
			}
		}()
	}

	switch data.Portnum {
	case pb.PortNum_NODEINFO_APP:
		user := &pb.User{}
		if err := proto.Unmarshal(data.Payload, user); err != nil {
			n.base.log.Debug("failed to unmarshal NodeInfo", "error", err)
			return
		}
		if n.base.pinIdentity(from, user, evt.IsSigned, core.ChannelIsAEAD(ch)) {
			n.db.Update(from, func(info *pb.NodeInfo) { info.User = user })
			// Remember which of our channels this node is reachable on.
			if ch != nil {
				n.db.SetChannel(from, ch)
			}
			n.base.emitEvent(&event.NodeInfoUpdated{Event: evt, User: user})
		}

		// Respond to NodeInfo requests with our own NodeInfo
		if data.WantResponse && n.requestIsForUs(pkt.Packet) && n.base.throttle.canRespond(core.NodeID(from), pb.PortNum_NODEINFO_APP) {
			replied = n.respondNodeInfo(from, pkt.Packet.Id)
		}

	case pb.PortNum_POSITION_APP:
		pos := &pb.Position{}
		if err := proto.Unmarshal(data.Payload, pos); err != nil {
			n.base.log.Debug("failed to unmarshal Position", "error", err)
			return
		}
		n.db.Update(from, func(info *pb.NodeInfo) { info.Position = pos })
		n.base.emitEvent(&event.PositionUpdated{Event: evt, Position: pos})

		if data.WantResponse && n.requestIsForUs(pkt.Packet) {
			replied = n.respondPosition(from, pkt.Packet.Id)
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

	case pb.PortNum_MESH_BEACON_APP:
		beacon := &pb.MeshBeacon{}
		if err := proto.Unmarshal(data.Payload, beacon); err != nil {
			n.base.log.Debug("failed to unmarshal MeshBeacon", "error", err)
			return
		}
		hasOffer := core.MeshBeaconHasOffer(beacon)
		if beacon.Message == "" && !hasOffer {
			return // nothing to act on, and firmware does not either
		}
		n.base.emitEvent(&event.MeshBeaconReceived{Event: evt, Beacon: beacon, HasOffer: hasOffer})

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
		// The peer could not decrypt our PKI packet for lack of our key, so send
		// it our NodeInfo, which carries it.
		if routing.GetErrorReason() == pb.Routing_PKI_UNKNOWN_PUBKEY && evt.To == n.cfg.NodeID &&
			n.hasPKI() && n.base.throttle.canRespond(evt.From, pb.PortNum_NODEINFO_APP) {
			n.respondNodeInfo(from, 0)
		}

	default:
		n.base.emitEvent(&event.PacketReceived{Event: evt})
	}
}
