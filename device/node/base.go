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
		channelName = b.primaryChannel
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
	if pkt.RxTime == 0 {
		pkt.RxTime = uint32(time.Now().Unix())
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
