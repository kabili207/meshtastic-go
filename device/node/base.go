package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/dedupe"
	"github.com/kabili207/meshtastic-go/core/lora"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/device/nodedb"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/raw"
	"google.golang.org/protobuf/proto"
)

const sendDelay = 200 * time.Millisecond

// baseNode holds the shared infrastructure used by both Node and BridgeNode:
// transport, channels, dedup, packet IDs, throttle, send pacing, and events.
type baseNode struct {
	transport raw.RawTransport
	channels  *core.ChannelRegistry
	dedup     *dedupe.PacketDeduplicator
	packetIDs packetIDGenerator
	throttle  *requestThrottle
	log       *slog.Logger
	nodeID    core.NodeID
	okToMQTT  bool
	hopLimit  uint32

	// primary is the first channel in the channel set, used when nothing else
	// selects one.
	primary core.ChannelDef
	// db is consulted when picking the channel for a unicast. Optional.
	db *nodedb.NodeDB

	// XEdDSA packet signing. See signing.go.
	signaturePolicy pb.Config_SecurityConfig_PacketSignaturePolicy
	licensed        bool
	privateKeyFor   func(core.NodeID) []byte
	publicKeyFor    func(core.NodeID) []byte

	sendMu   sync.Mutex
	lastSend time.Time

	eventMu       sync.RWMutex
	eventHandlers []event.Handler
}

// OnEvent registers an event handler. Handlers are called synchronously
// for each decoded packet. Safe to call from multiple goroutines.
func (b *baseNode) OnEvent(fn event.Handler) {
	b.eventMu.Lock()
	defer b.eventMu.Unlock()
	b.eventHandlers = append(b.eventHandlers, fn)
}

func (b *baseNode) emitEvent(evt any) {
	b.eventMu.RLock()
	handlers := b.eventHandlers
	b.eventMu.RUnlock()
	for _, fn := range handlers {
		fn(evt)
	}
}

// sendPacket sends on the channel with the given name, or, when the name is
// empty, on the channel a unicast destination was last heard on, falling back to
// the primary. A name shared by more than one registered channel is an error
// rather than a guess: use sendPacketOn with the exact channel instead.
func (b *baseNode) sendPacket(ctx context.Context, packet *pb.MeshPacket, channelName string) error {
	var ch core.ChannelDef
	if channelName != "" {
		resolved, err := b.channels.ResolveByName(channelName)
		if err != nil {
			return fmt.Errorf("channel %q: %w", channelName, err)
		}
		ch = resolved
	} else {
		ch = b.channelForDestination(core.NodeID(packet.To), packet.PkiEncrypted)
	}
	return b.sendPacketOn(ctx, packet, ch, false)
}

// sendPacketWith sends honoring the channel chosen by send options: an exact
// channel first, then a name, then the destination's channel.
func (b *baseNode) sendPacketWith(ctx context.Context, packet *pb.MeshPacket, o sendOptions) error {
	if decoded := packet.GetDecoded(); decoded != nil {
		markAutomation(decoded, o)
	}
	ch := o.channelDef
	if ch == nil {
		if o.channel != "" {
			resolved, err := b.channels.ResolveByName(o.channel)
			if err != nil {
				return fmt.Errorf("channel %q: %w", o.channel, err)
			}
			ch = resolved
		} else {
			ch = b.channelForDestination(core.NodeID(packet.To), false)
		}
	}
	return b.sendPacketOn(ctx, packet, ch, o.usePKI)
}

// sendPacketOn stamps a packet ID, applies defaults, signs and encrypts a
// decoded payload (see encryptOutbound), and sends on that channel's transport
// topic. requirePKI fails the send rather than falling back to the channel key.
func (b *baseNode) sendPacketOn(_ context.Context, packet *pb.MeshPacket, ch core.ChannelDef, requirePKI bool) error {
	packet.Id = b.packetIDs.next()

	b.applyPacketDefaults(packet)

	if decoded := packet.GetDecoded(); decoded != nil {
		decoded.Bitfield = proto.Uint32(b.outboundBitfield(decoded.GetBitfield(), decoded.WantResponse))
	}

	if err := b.encryptOutbound(packet, ch, requirePKI); err != nil {
		return err
	}

	b.sendMu.Lock()
	defer b.sendMu.Unlock()

	// Pace outbound packets so radio hardware has time to switch between
	// TX and RX modes. Without this, burst-sending can cause packet loss.
	if !b.lastSend.IsZero() {
		if elapsed := time.Since(b.lastSend); elapsed < sendDelay {
			time.Sleep(sendDelay - elapsed)
		}
	}
	b.lastSend = time.Now()

	return b.transport.SendPacket(ch.GetName(), packet)
}

// channelForDestination picks the channel for a packet with none specified. A
// unicast goes out on the channel we last heard the destination's NodeInfo on,
// which is how firmware reaches a node it shares a secondary channel with.
// Everything else, and any node we have not heard from, uses the primary.
func (b *baseNode) channelForDestination(to core.NodeID, pki bool) core.ChannelDef {
	if pki || to == 0 || to.IsBroadcast() || b.db == nil {
		return b.primary
	}
	if ch, ok := b.db.Channel(to.Uint32()); ok {
		return ch
	}
	return b.primary
}

// applyPacketDefaults fills in HopLimit, HopStart, Priority, and RxTime
// when the caller has not set them explicitly. The hopLimit is taken from
// the baseNode's configured default rather than from a Config struct.
func (b *baseNode) applyPacketDefaults(pkt *pb.MeshPacket) {
	if pkt.HopLimit == 0 {
		pkt.HopLimit = b.hopLimit
	}
	if pkt.HopStart == 0 {
		pkt.HopStart = pkt.HopLimit
	}
	if pkt.Priority == pb.MeshPacket_UNSET {
		pkt.Priority = lora.GetPriority(pkt.GetDecoded(), pkt.WantAck)
	}
	if pkt.RxTime == nil {
		pkt.RxTime = proto.Uint32(uint32(time.Now().Unix()))
	}
	if pkt.RelayNode == 0 {
		pkt.RelayNode = b.nodeID.Uint32() & 0xFF
	}
}

var (
	// ErrNoPublicKey reports a unicast that firmware would PKI-encrypt to a node
	// whose key we do not hold. Firmware refuses these (PKI_SEND_FAIL_PUBLIC_KEY)
	// rather than falling back to the channel key, since receivers reject a
	// channel-encrypted DM.
	ErrNoPublicKey = errors.New("no public key for destination")
	// ErrPKIUnavailable reports a send that required PKI for a packet that cannot
	// use it: a broadcast, a port firmware never PKI-encrypts, or a sender without
	// a private key.
	ErrPKIUnavailable = errors.New("packet cannot be sent with PKI")
	// ErrPacketTooLarge reports a packet that does not fit a LoRa frame once
	// encrypted.
	ErrPacketTooLarge = errors.New("packet too large to send")
)

// encryptOutbound signs and encrypts the decoded payload of a packet we
// originate. It uses PKI exactly when firmware's wouldEncryptWithPKC would, and
// the channel's key otherwise. A packet that is not decoded is left alone.
func (b *baseNode) encryptOutbound(pkt *pb.MeshPacket, ch core.ChannelDef, requirePKI bool) error {
	data := pkt.GetDecoded()
	if data == nil {
		return nil
	}
	from, to := core.NodeID(pkt.From), core.NodeID(pkt.To)
	var priv []byte
	if b.privateKeyFor != nil && usesPKI(data.Portnum, to, b.licensed) {
		priv = b.privateKeyFor(from)
	}
	pki := priv != nil
	if requirePKI && !pki {
		return fmt.Errorf("%w: %v to %s", ErrPKIUnavailable, data.Portnum, to)
	}

	aead := !pki && core.ChannelIsAEAD(ch)
	b.signOutbound(data, pkt.From, pkt.Id, to, pki || aead)
	plaintext, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling data: %w", err)
	}

	if aead {
		if len(plaintext)+crypto.AEADOverhead+core.LoraHeaderLength > core.MaxLoraPayload {
			return fmt.Errorf("%w: %d bytes with AEAD overhead", ErrPacketTooLarge, len(plaintext)+crypto.AEADOverhead)
		}
		encrypted, err := crypto.EncryptAEAD(plaintext, ch.GetKeyBytes(), pkt.Id, pkt.From, pkt.To)
		if err != nil {
			return fmt.Errorf("AEAD encrypt: %w", err)
		}
		pkt.Channel = ch.GetHash()
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{Encrypted: encrypted}
		return nil
	}
	if !pki {
		if pkt.Channel == 0 {
			pkt.Channel = ch.GetHash()
		}
		encrypted, err := crypto.XOR(plaintext, ch.GetKeyBytes(), pkt.Id, pkt.From)
		if err != nil {
			return fmt.Errorf("XOR encrypt: %w", err)
		}
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{Encrypted: encrypted}
		return nil
	}

	if len(plaintext)+crypto.MeshtasticPKCOverhead+core.LoraHeaderLength > core.MaxLoraPayload {
		return fmt.Errorf("%w: %d bytes with PKI overhead", ErrPacketTooLarge, len(plaintext)+crypto.MeshtasticPKCOverhead)
	}
	pub := b.lookupPublicKey(to)
	if pub == nil {
		return fmt.Errorf("%w %s", ErrNoPublicKey, to)
	}
	encrypted, err := crypto.EncryptCurve25519(plaintext, priv, pub, pkt.Id, pkt.From)
	if err != nil {
		return fmt.Errorf("PKI encrypt: %w", err)
	}
	pkt.Channel = 0
	pkt.PkiEncrypted = true
	pkt.PayloadVariant = &pb.MeshPacket_Encrypted{Encrypted: encrypted}
	return nil
}

// outboundBitfield builds the Data bitfield for a packet we originate. Like
// firmware's perhapsEncode, the field is always present, carrying the configured
// MQTT consent and mirroring want_response, on top of any bits already set.
func (b *baseNode) outboundBitfield(bits uint32, wantResponse bool) uint32 {
	if b.okToMQTT {
		bits |= bitfieldOkToMQTT
	}
	if wantResponse {
		bits |= bitfieldWantResponse
	}
	return bits
}

// decodeOn decrypts a packet with a channel's key, using AES-CCM on an AEAD
// channel. Firmware never falls back to AES-CTR there: a tag that does not
// verify means the packet is not for that channel.
func decodeOn(pkt *pb.MeshPacket, ch core.ChannelDef) (*pb.Data, error) {
	if !core.ChannelIsAEAD(ch) {
		return crypto.TryDecode(pkt, ch.GetKeyBytes())
	}
	plain, err := crypto.DecryptAEAD(pkt.GetEncrypted(), ch.GetKeyBytes(), pkt.Id, pkt.From, pkt.To)
	if err != nil {
		return nil, err
	}
	data := &pb.Data{}
	if err := proto.Unmarshal(plain, data); err != nil {
		return nil, crypto.ErrDecrypt
	}
	return data, nil
}

// isLegacyDM reports whether a channel-decrypted packet is a text DM to one of
// our identities. Firmware has rejected these since 2.7.14, so a sender cannot
// skip PKI. Without a private key for the recipient we have no PKI, and like a
// firmware build without it we accept them. Licensed nodes never use PKI.
func (b *baseNode) isLegacyDM(pkt *pb.MeshPacket, data *pb.Data) bool {
	to := core.NodeID(pkt.To)
	return data.Portnum == pb.PortNum_TEXT_MESSAGE_APP && !b.licensed && !to.IsBroadcast() &&
		b.privateKeyFor != nil && b.privateKeyFor(to) != nil
}

// usesPKI reports whether firmware would PKI-encrypt a packet it originates,
// given a private key to do it with: every unicast except traceroute, NodeInfo,
// routing, and position. Licensed nodes never use PKI, since amateur radio rules
// forbid encryption.
func usesPKI(portnum pb.PortNum, to core.NodeID, licensed bool) bool {
	if licensed || to.IsBroadcast() {
		return false
	}
	switch portnum {
	case pb.PortNum_TRACEROUTE_APP, pb.PortNum_NODEINFO_APP, pb.PortNum_ROUTING_APP, pb.PortNum_POSITION_APP:
		return false
	}
	return true
}

// decodedChannel resolves the channel of an already-decoded packet. Its channel
// field is a channel index rather than a hash, so the transport's channel name is
// used when it supplies one, with the hash lookup as a fallback. The definition
// is nil when the name is unknown or shared by more than one registered channel,
// since a decoded packet carries nothing that could tell them apart.
func (b *baseNode) decodedChannel(pkt transport.NetworkPacket) (core.ChannelDef, string) {
	name := pkt.Channel
	if name == "" {
		name = b.channels.LookupName(pkt.Packet.Channel)
	}
	ch, _ := b.channels.LookupByName(name)
	return ch, name
}
