package node

import (
	"bytes"
	"context"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

var aeadKey = bytes.Repeat([]byte{0x5A}, 32)

// aeadNode is a node with its own identity on a single AEAD channel.
func aeadNode(t *testing.T, mt *mockTransport, policy pb.Config_SecurityConfig_PacketSignaturePolicy, events *[]any) *Node {
	t.Helper()
	self := newIdentity(t, 0x11)
	return newTestNode(t, mt, func(c *Config) {
		c.NodeID, c.PrivateKey, c.PublicKey = self.id, self.priv, self.pub
		c.SignaturePolicy = policy
		c.Channels = &pb.ChannelSet{Settings: []*pb.ChannelSettings{{Name: "Secure", Psk: aeadKey, UseAead: true}}}
		c.EventHandlers = []event.Handler{func(evt any) { *events = append(*events, evt) }}
	})
}

func aeadPacket(t *testing.T, from, to core.NodeID, id uint32, data *pb.Data) transport.NetworkPacket {
	t.Helper()
	raw, _ := proto.Marshal(data)
	enc, err := crypto.EncryptAEAD(raw, aeadKey, id, from.Uint32(), to.Uint32())
	if err != nil {
		t.Fatal(err)
	}
	return transport.NetworkPacket{Channel: "Secure", Packet: &pb.MeshPacket{
		Id: id, From: from.Uint32(), To: to.Uint32(),
		Channel:        crypto.ChannelHash("Secure", aeadKey) ^ 0xAE,
		PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: enc},
	}}
}

// An AEAD channel encrypts with AES-CCM under a hash XORed with 0xAE, and its tag
// stands in for a signature.
func TestAEADSend(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n := aeadNode(t, mt, 0, &events)
	if err := n.SendText(context.Background(), core.BroadcastNodeID, "sealed"); err != nil {
		t.Fatal(err)
	}
	sent := mt.lastSent().packet
	if want := crypto.ChannelHash("Secure", aeadKey) ^ 0xAE; sent.Channel != want {
		t.Errorf("channel hash %d, want %d", sent.Channel, want)
	}
	plain, err := crypto.DecryptAEAD(sent.GetEncrypted(), aeadKey, sent.Id, sent.From, sent.To)
	if err != nil {
		t.Fatalf("sent packet is not AES-CCM under the channel key: %v", err)
	}
	data := &pb.Data{}
	if err := proto.Unmarshal(plain, data); err != nil || string(data.Payload) != "sealed" {
		t.Fatalf("decrypted payload: %v", err)
	}
	if data.XeddsaSignature != nil {
		t.Error("a broadcast on an AEAD channel was signed")
	}
}

func TestAEADReceive(t *testing.T) {
	text := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hello")}

	t.Run("decrypts and accepts unsigned even under STRICT", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n := aeadNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT, &events)
		inject(n, mt, aeadPacket(t, 0xAA, core.BroadcastNodeID, 1, text))
		if msgs := textEvents(events); len(msgs) != 1 || msgs[0].Message != "hello" {
			t.Errorf("got %d text events, want the AEAD message", len(msgs))
		}
	})

	t.Run("no fallback to AES-CTR", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n := aeadNode(t, mt, 0, &events)
		pkt := aeadPacket(t, 0xAA, core.BroadcastNodeID, 2, text)
		raw, _ := proto.Marshal(text)
		ctr, _ := crypto.XOR(raw, aeadKey, 2, 0xAA)
		pkt.Packet.PayloadVariant = &pb.MeshPacket_Encrypted{Encrypted: ctr}
		inject(n, mt, pkt)
		if len(textEvents(events)) != 0 {
			t.Error("a CTR packet was accepted on an AEAD channel")
		}
	})

	t.Run("re-addressed packet fails its tag", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n := aeadNode(t, mt, 0, &events)
		pkt := aeadPacket(t, 0xAA, 0xBB, 3, text)
		pkt.Packet.To = core.BroadcastNodeID.Uint32()
		inject(n, mt, pkt)
		if len(textEvents(events)) != 0 {
			t.Error("a re-addressed AEAD packet was accepted")
		}
	})
}

// A channel resolving to no key cannot run AEAD, so firmware clears the flag.
func TestAEADNeedsAKey(t *testing.T) {
	ch := core.ChannelFromSettings(&pb.ChannelSettings{Name: "Open", Psk: []byte{0}, UseAead: true})
	if core.ChannelIsAEAD(ch) {
		t.Error("a keyless channel kept use_aead")
	}
}

// BALANCED refuses unsigned identity changes from a known signer, but not on an
// AEAD channel, where the tag authenticates the sender's channel membership.
func TestAEADExemptsUnsignedIdentityRefusal(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n := aeadNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_BALANCED, &events)
	n.NodeDB().Update(0xAA, func(info *pb.NodeInfo) { info.HasXeddsaSigned = true })
	if n.base.pinIdentity(0xAA, &pb.User{LongName: "Renamed"}, false, false) {
		t.Error("BALANCED accepted an unsigned update from a signer off AEAD")
	}
	if !n.base.pinIdentity(0xAA, &pb.User{LongName: "Renamed"}, false, true) {
		t.Error("an unsigned update on an AEAD channel was refused")
	}
}
