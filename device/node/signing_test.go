package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// A deterministic X25519 identity for a peer. The node ID is what firmware 2.8
// would assign it, so first-contact bootstrap can bind the two.
type testIdentity struct {
	priv, pub []byte
	id        core.NodeID
}

func newIdentity(t *testing.T, seed byte) testIdentity {
	t.Helper()
	priv := make([]byte, crypto.PublicKeySize)
	for i := range priv {
		priv[i] = seed + byte(i*3)
	}
	priv[0] &= 0xF8
	priv[31] &= 0x7F
	priv[31] |= 0x40
	pub, err := crypto.PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := core.NodeIDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{priv: priv, pub: pub, id: id}
}

func signedData(t *testing.T, ident testIdentity, packetID uint32, portnum pb.PortNum, payload []byte) *pb.Data {
	t.Helper()
	sig, err := crypto.SignPacketData(ident.priv, ident.id.Uint32(), packetID, portnum, payload)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.Data{Portnum: portnum, Payload: payload, XeddsaSignature: sig}
}

func decodedPacket(from core.NodeID, to core.NodeID, id uint32, data *pb.Data) transport.NetworkPacket {
	return transport.NetworkPacket{
		Channel: "LongFast",
		Packet: &pb.MeshPacket{
			Id:             id,
			From:           from.Uint32(),
			To:             to.Uint32(),
			PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
		},
	}
}

// signingNode builds a Node with its own identity and an event recorder.
func signingNode(t *testing.T, mt *mockTransport, policy pb.Config_SecurityConfig_PacketSignaturePolicy, events *[]any) (*Node, testIdentity) {
	t.Helper()
	self := newIdentity(t, 0x11)
	n := newTestNode(t, mt, func(c *Config) {
		c.NodeID = self.id
		c.PrivateKey = self.priv
		c.PublicKey = self.pub
		c.SignaturePolicy = policy
		c.EventHandlers = []event.Handler{func(evt any) { *events = append(*events, evt) }}
	})
	return n, self
}

// decryptSent recovers the Data from the last PSK-encrypted packet the node sent.
func decryptSent(t *testing.T, mt *mockTransport) (*pb.MeshPacket, *pb.Data) {
	t.Helper()
	sent := mt.lastSent().packet
	data, err := crypto.TryDecode(sent, crypto.DefaultKey)
	if err != nil {
		t.Fatalf("decrypting sent packet: %v", err)
	}
	return sent, data
}

func TestSignOutboundBroadcast(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, self := signingNode(t, mt, 0, &events)

	if err := n.SendText(context.Background(), core.BroadcastNodeID, "signed hello"); err != nil {
		t.Fatal(err)
	}
	sent, data := decryptSent(t, mt)

	if len(data.XeddsaSignature) != crypto.XEdDSASignatureSize {
		t.Fatalf("broadcast was not signed: signature is %d bytes", len(data.XeddsaSignature))
	}
	if !crypto.VerifyPacketData(self.pub, sent.From, sent.Id, data.Portnum, data.Payload, data.XeddsaSignature) {
		t.Error("signature does not verify under the node's own key")
	}
}

func TestSignOutboundUnicastOnlyWhenLicensed(t *testing.T) {
	t.Run("unlicensed unicast is unsigned", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n, _ := signingNode(t, mt, 0, &events)
		if err := n.SendText(context.Background(), 0xAA, "dm"); err != nil {
			t.Fatal(err)
		}
		if _, data := decryptSent(t, mt); data.XeddsaSignature != nil {
			t.Error("unlicensed unicast carried a signature")
		}
	})

	t.Run("licensed unicast is signed", func(t *testing.T) {
		mt := newMockTransport()
		self := newIdentity(t, 0x11)
		n := newTestNode(t, mt, func(c *Config) {
			c.NodeID, c.PrivateKey, c.PublicKey = self.id, self.priv, self.pub
			c.Licensed = true
		})
		if err := n.SendText(context.Background(), 0xAA, "dm"); err != nil {
			t.Fatal(err)
		}
		if _, data := decryptSent(t, mt); len(data.XeddsaSignature) != crypto.XEdDSASignatureSize {
			t.Error("licensed unicast was not signed")
		}
	})
}

func TestSignOutboundSkipsWhenSignedWouldNotFit(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)

	// Fits unsigned, would not fit with 66 more bytes alongside the 16-byte header.
	big := make([]byte, 200)
	if err := n.SendText(context.Background(), core.BroadcastNodeID, string(big)); err != nil {
		t.Fatal(err)
	}
	if _, data := decryptSent(t, mt); data.XeddsaSignature != nil {
		t.Error("signed a payload that would not fit the frame")
	}
}

func TestSignOutboundWithoutKeyIsUnsigned(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt) // no PrivateKey
	if err := n.SendText(context.Background(), core.BroadcastNodeID, "hi"); err != nil {
		t.Fatal(err)
	}
	if _, data := decryptSent(t, mt); data.XeddsaSignature != nil {
		t.Error("a node without a key produced a signature")
	}
}

func textEvents(events []any) []*event.TextMessage {
	var out []*event.TextMessage
	for _, e := range events {
		if tm, ok := e.(*event.TextMessage); ok {
			out = append(out, tm)
		}
	}
	return out
}

func TestReceiveSignedFromKnownKey(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)
	peer := newIdentity(t, 0x22)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) {
		info.User = &pb.User{PublicKey: peer.pub}
	})

	data := signedData(t, peer, 50, pb.PortNum_TEXT_MESSAGE_APP, []byte("verified"))
	inject(n, mt, decodedPacket(peer.id, core.BroadcastNodeID, 50, data))

	msgs := textEvents(events)
	if len(msgs) != 1 {
		t.Fatalf("got %d text events, want 1", len(msgs))
	}
	if !msgs[0].IsSigned {
		t.Error("verified packet was not reported as signed")
	}
	if info := n.NodeDB().Get(peer.id.Uint32()); info == nil || !info.HasXeddsaSigned {
		t.Error("peer was not marked as a known signer")
	}
}

func TestReceiveDropsBadSignature(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)
	peer := newIdentity(t, 0x22)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) {
		info.User = &pb.User{PublicKey: peer.pub}
	})

	data := signedData(t, peer, 51, pb.PortNum_TEXT_MESSAGE_APP, []byte("tampered"))
	data.Payload = []byte("tamperee")
	inject(n, mt, decodedPacket(peer.id, core.BroadcastNodeID, 51, data))

	if len(textEvents(events)) != 0 {
		t.Error("a packet with a bad signature was accepted")
	}
}

func TestReceiveDropsMalformedSignature(t *testing.T) {
	for _, policy := range []pb.Config_SecurityConfig_PacketSignaturePolicy{0, 1, 2} {
		mt := newMockTransport()
		var events []any
		n, _ := signingNode(t, mt, policy, &events)

		data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("x"), XeddsaSignature: make([]byte, 10)}
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 52, data))

		if len(textEvents(events)) != 0 {
			t.Errorf("policy %v: a 10-byte signature was accepted", policy)
		}
	}
}

func TestReceiveFirstContactBootstrap(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT, &events)
	peer := newIdentity(t, 0x33)

	userBytes, _ := proto.Marshal(&pb.User{LongName: "Newcomer", PublicKey: peer.pub})
	data := signedData(t, peer, 60, pb.PortNum_NODEINFO_APP, userBytes)
	inject(n, mt, decodedPacket(peer.id, core.BroadcastNodeID, 60, data))

	info := n.NodeDB().Get(peer.id.Uint32())
	if info == nil || !info.HasXeddsaSigned {
		t.Fatal("first-contact NodeInfo did not establish the peer as a signer")
	}
	if string(info.User.PublicKey) != string(peer.pub) {
		t.Error("carried key was not stored")
	}
	if info.User.LongName != "Newcomer" {
		t.Error("NodeInfo was not applied after bootstrap")
	}
}

// A node may not introduce itself under an ID its key does not derive.
func TestReceiveFirstContactRejectsMismatchedID(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)
	peer := newIdentity(t, 0x33)
	claimed := peer.id ^ 1

	userBytes, _ := proto.Marshal(&pb.User{PublicKey: peer.pub})
	sig, err := crypto.SignPacketData(peer.priv, claimed.Uint32(), 61, pb.PortNum_NODEINFO_APP, userBytes)
	if err != nil {
		t.Fatal(err)
	}
	data := &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes, XeddsaSignature: sig}
	inject(n, mt, decodedPacket(claimed, core.BroadcastNodeID, 61, data))

	if n.NodeDB().Get(claimed.Uint32()) != nil {
		t.Error("a NodeInfo under a mismatched ID was stored")
	}
}

func TestReceiveStrictDropsUnsigned(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT, &events)

	data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("unsigned")}
	inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 70, data))

	if len(textEvents(events)) != 0 {
		t.Error("STRICT accepted an unsigned packet")
	}
}

func TestReceiveCompatibleAcceptsUnsigned(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_COMPATIBLE, &events)

	data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("unsigned")}
	inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 71, data))

	msgs := textEvents(events)
	if len(msgs) != 1 {
		t.Fatalf("got %d events, want 1", len(msgs))
	}
	if msgs[0].IsSigned {
		t.Error("an unsigned packet was reported as signed")
	}
}

func TestReceiveBalanced(t *testing.T) {
	newBalanced := func(t *testing.T) (*Node, *mockTransport, *[]any, testIdentity) {
		mt := newMockTransport()
		var events []any
		n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_BALANCED, &events)
		signer := newIdentity(t, 0x44)
		n.NodeDB().Update(signer.id.Uint32(), func(info *pb.NodeInfo) {
			info.User = &pb.User{PublicKey: signer.pub}
			info.HasXeddsaSigned = true
		})
		return n, mt, &events, signer
	}

	t.Run("unsigned broadcast from a known signer is dropped", func(t *testing.T) {
		n, mt, events, signer := newBalanced(t)
		data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("downgrade")}
		inject(n, mt, decodedPacket(signer.id, core.BroadcastNodeID, 80, data))
		if len(textEvents(*events)) != 0 {
			t.Error("downgrade was accepted")
		}
	})

	t.Run("unsigned unicast from a known signer is accepted when unlicensed", func(t *testing.T) {
		n, mt, events, signer := newBalanced(t)
		data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("dm")}
		inject(n, mt, decodedPacket(signer.id, n.cfg.NodeID, 81, data))
		if len(textEvents(*events)) != 1 {
			t.Error("unsigned unicast from a signer was dropped without a licensed rule")
		}
	})

	t.Run("unsigned broadcast from an unknown node is accepted", func(t *testing.T) {
		n, mt, events, _ := newBalanced(t)
		data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("stranger")}
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 82, data))
		if len(textEvents(*events)) != 1 {
			t.Error("unsigned packet from an unknown node was dropped")
		}
	})

	t.Run("oversized unsigned broadcast from a signer is accepted", func(t *testing.T) {
		n, mt, events, signer := newBalanced(t)
		// A signer could not have fit a signature on this, so unsigned is not a downgrade.
		data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: make([]byte, 200)}
		inject(n, mt, decodedPacket(signer.id, core.BroadcastNodeID, 83, data))
		if len(textEvents(*events)) != 1 {
			t.Error("an unsignable broadcast was treated as a downgrade")
		}
	})
}

// Unknown-field padding inside a typed payload must not let a forger inflate an
// unsigned broadcast past the signable budget.
func TestCanonicalSignableSizeStripsPadding(t *testing.T) {
	position, _ := proto.Marshal(&pb.Position{LatitudeI: proto.Int32(1), LongitudeI: proto.Int32(2)})
	clean := &pb.Data{Portnum: pb.PortNum_POSITION_APP, Payload: position}

	// Field 999 with 150 bytes of junk: valid protobuf, unknown to Position.
	padding := protowire.AppendTag(nil, 999, protowire.BytesType)
	padding = protowire.AppendBytes(padding, make([]byte, 150))
	padded := &pb.Data{Portnum: pb.PortNum_POSITION_APP, Payload: append(append([]byte{}, position...), padding...)}

	if got, want := canonicalSignableSize(padded), canonicalSignableSize(clean); got != want {
		t.Errorf("padded size %d, want canonical %d", got, want)
	}
	if proto.Size(padded) <= proto.Size(clean) {
		t.Fatal("test setup: padding did not grow the raw size")
	}
}

func TestPinIdentity(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)
	held := newIdentity(t, 0x55)
	planted := newIdentity(t, 0x66)

	t.Run("unsigned NodeInfo cannot replace a held key", func(t *testing.T) {
		n.NodeDB().Update(0xAA, func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: held.pub} })
		userBytes, _ := proto.Marshal(&pb.User{LongName: "Renamed", PublicKey: planted.pub})
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 90, &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes}))

		info := n.NodeDB().Get(0xAA)
		if string(info.User.PublicKey) != string(held.pub) {
			t.Error("an unsigned NodeInfo replaced the held key")
		}
		if info.User.LongName != "Renamed" {
			t.Error("the non-key fields of the NodeInfo were not applied")
		}
	})

	t.Run("unsigned NodeInfo cannot erase a held key", func(t *testing.T) {
		userBytes, _ := proto.Marshal(&pb.User{LongName: "Keyless"})
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 91, &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes}))
		if info := n.NodeDB().Get(0xAA); string(info.User.PublicKey) != string(held.pub) {
			t.Error("an unsigned NodeInfo without a key erased the held key")
		}
	})

	t.Run("known signer sending unsigned is ignored", func(t *testing.T) {
		n.NodeDB().Update(0xBB, func(info *pb.NodeInfo) {
			info.User = &pb.User{LongName: "Signer", PublicKey: held.pub}
			info.HasXeddsaSigned = true
		})
		userBytes, _ := proto.Marshal(&pb.User{LongName: "Impostor", PublicKey: held.pub})
		inject(n, mt, decodedPacket(0xBB, core.BroadcastNodeID, 92, &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes}))
		if info := n.NodeDB().Get(0xBB); info.User.LongName != "Signer" {
			t.Error("an unsigned NodeInfo rewrote a known signer's identity")
		}
	})
}

// An inbound xeddsa_signed flag must never survive to the event.
func TestInboundSignedFlagIsNotTrusted(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)

	pkt := decodedPacket(0xAA, core.BroadcastNodeID, 95, &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("claim")})
	pkt.Packet.XeddsaSigned = true
	inject(n, mt, pkt)

	msgs := textEvents(events)
	if len(msgs) != 1 {
		t.Fatalf("got %d events, want 1", len(msgs))
	}
	if msgs[0].IsSigned || pkt.Packet.XeddsaSigned {
		t.Error("the wire's xeddsa_signed claim was honored")
	}
}
