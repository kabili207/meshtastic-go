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

	// primaryChannel is the name of the first channel in the channel set.
	primaryChannel string
	// channelNames is the configured channel set in index order, so a channel
	// index stored in the nodedb can be mapped back to a name and vice versa.
	channelNames []string
	// db is consulted when picking the channel for a unicast. Optional.
	db *nodedb.NodeDB

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

// sendPacket stamps a packet ID, applies defaults, encrypts decoded payloads,
// and sends via the specified channel. If channelName is empty, the primary
// channel is used.
func (b *baseNode) sendPacket(_ context.Context, packet *pb.MeshPacket, channelName string) error {
	packet.Id = b.packetIDs.next()

	if channelName == "" {
		channelName = b.channelForDestination(core.NodeID(packet.To), packet.PkiEncrypted)
	}

	// Resolve channel definition for hash and encryption key.
	var ch core.ChannelDef
	if !packet.PkiEncrypted {
		if found, ok := b.channels.LookupByName(channelName); ok {
			ch = found
			if packet.Channel == 0 {
				packet.Channel = ch.GetHash()
			}
		}
	}

	b.applyPacketDefaults(packet)

	// Set OK-to-MQTT bitfield flag on outbound Data payloads.
	if b.okToMQTT {
		if decoded := packet.GetDecoded(); decoded != nil {
			bf := decoded.GetBitfield() | 1 // bit 0 = OK to MQTT
			decoded.Bitfield = &bf
		}
	}

	// PSK-encrypt decoded payloads so other nodes can receive them.
	if decoded := packet.GetDecoded(); decoded != nil && ch != nil {
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

	return b.transport.SendPacket(channelName, packet)
}

// channelNamesFrom returns the channel set's names in index order.
func channelNamesFrom(set *pb.ChannelSet) []string {
	names := make([]string, 0, len(set.Settings))
	for _, s := range set.Settings {
		names = append(names, s.Name)
	}
	return names
}

// channelIndex maps a configured channel name to its index. Names that are not
// configured channels, such as the "PKI" pseudo-channel, report false.
func (b *baseNode) channelIndex(name string) (uint32, bool) {
	for i, n := range b.channelNames {
		if n == name {
			return uint32(i), true
		}
	}
	return 0, false
}

// channelForDestination picks the channel for a packet with none specified. A
// unicast goes out on the channel we last heard the destination's NodeInfo on,
// which is how firmware reaches a node it shares a secondary channel with.
// Everything else, and any node we have not heard from, uses the primary.
func (b *baseNode) channelForDestination(to core.NodeID, pki bool) string {
	if pki || to == 0 || to.IsBroadcast() || b.db == nil {
		return b.primaryChannel
	}
	if info := b.db.Get(to.Uint32()); info != nil && int(info.Channel) < len(b.channelNames) {
		return b.channelNames[info.Channel]
	}
	return b.primaryChannel
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
// used when it supplies one, with the hash lookup as a fallback. The registered
// key is returned so consumers can identify the channel the same way they would
// for a packet decrypted locally.
func (b *baseNode) decodedChannel(pkt transport.NetworkPacket) (string, *string) {
	name := pkt.Channel
	if name == "" {
		name = b.channels.LookupName(pkt.Packet.Channel)
	}
	if ch, ok := b.channels.LookupByName(name); ok {
		key := ch.GetKeyString()
		return name, &key
	}
	return name, nil
}
