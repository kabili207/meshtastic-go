package node

import (
	"context"
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
	return b.sendPacketOn(ctx, packet, ch)
}

// sendPacketWith sends honoring the channel chosen by send options: an exact
// channel first, then a name, then the destination's channel.
func (b *baseNode) sendPacketWith(ctx context.Context, packet *pb.MeshPacket, o sendOptions) error {
	if o.channelDef != nil {
		return b.sendPacketOn(ctx, packet, o.channelDef)
	}
	return b.sendPacket(ctx, packet, o.channel)
}

// sendPacketOn stamps a packet ID, applies defaults, signs and PSK-encrypts a
// decoded payload with the channel's key, and sends on that channel's transport
// topic. A PKI packet is already encrypted; the channel then only names the topic.
func (b *baseNode) sendPacketOn(_ context.Context, packet *pb.MeshPacket, ch core.ChannelDef) error {
	packet.Id = b.packetIDs.next()

	if !packet.PkiEncrypted && packet.Channel == 0 {
		packet.Channel = ch.GetHash()
	}

	b.applyPacketDefaults(packet)

	// Set OK-to-MQTT bitfield flag on outbound Data payloads.
	if b.okToMQTT {
		if decoded := packet.GetDecoded(); decoded != nil {
			bf := decoded.GetBitfield() | 1 // bit 0 = OK to MQTT
			decoded.Bitfield = &bf
		}
	}

	if decoded := packet.GetDecoded(); decoded != nil {
		b.signOutbound(decoded, packet.From, packet.Id, core.NodeID(packet.To), packet.PkiEncrypted)
	}

	// PSK-encrypt decoded payloads so other nodes can receive them.
	if decoded := packet.GetDecoded(); decoded != nil && !packet.PkiEncrypted {
		if err := encryptDecoded(packet, decoded, ch.GetKeyBytes()); err != nil {
			return fmt.Errorf("encrypting packet: %w", err)
		}
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

// encryptDecoded marshals a Decoded payload and replaces it with an Encrypted
// variant using AES-CTR (PSK encryption).
func encryptDecoded(pkt *pb.MeshPacket, data *pb.Data, key []byte) error {
	plaintext, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling data: %w", err)
	}
	encrypted, err := crypto.XOR(plaintext, key, pkt.Id, pkt.From)
	if err != nil {
		return fmt.Errorf("XOR encrypt: %w", err)
	}
	pkt.PayloadVariant = &pb.MeshPacket_Encrypted{
		Encrypted: encrypted,
	}
	return nil
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
