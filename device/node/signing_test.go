package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
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

func signedData(t *testing.T, ident testIdentity, packetID uint32, to core.NodeID, portnum pb.PortNum, payload []byte) *pb.Data {
	t.Helper()
	data := &pb.Data{Portnum: portnum, Payload: payload}
	sig, err := crypto.SignPacketData(ident.priv, ident.id.Uint32(), packetID, to.Uint32(), data)
	if err != nil {
		t.Fatal(err)
	}
	data.XeddsaSignature = sig
	return data
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
	if !crypto.VerifyPacketData(self.pub, sent.From, sent.Id, sent.To, data, data.XeddsaSignature) {
		t.Error("signature does not verify under the node's own key")
	}
}

// Mirrors firmware's perhapsEncode matrix (test_packet_signing B7, B13, B21-B24).
func TestSignableOutbound(t *testing.T) {
	const peer = core.NodeID(0xAA)
	tests := []struct {
		portnum  pb.PortNum
		to       core.NodeID
		licensed bool
		want     bool
	}{
		{pb.PortNum_TEXT_MESSAGE_APP, core.BroadcastNodeID, false, true},
		{pb.PortNum_TEXT_MESSAGE_APP, peer, false, false},
		{pb.PortNum_TELEMETRY_APP, peer, false, false},
		{pb.PortNum_NODEINFO_APP, peer, false, true},
		{pb.PortNum_POSITION_APP, peer, false, true},
		{pb.PortNum_ROUTING_APP, peer, false, false},
		{pb.PortNum_TRACEROUTE_APP, core.BroadcastNodeID, false, false},
		{pb.PortNum_TRACEROUTE_APP, peer, true, false},
		{pb.PortNum_TEXT_MESSAGE_APP, peer, true, true},
		{pb.PortNum_ROUTING_APP, peer, true, false},
		{pb.PortNum_ROUTING_APP, core.BroadcastNodeID, true, true},
	}
	for _, tt := range tests {
		if got := signableOutbound(tt.portnum, tt.to, tt.licensed); got != tt.want {
			t.Errorf("signableOutbound(%v, %v, licensed=%v) = %v, want %v", tt.portnum, tt.to, tt.licensed, got, tt.want)
		}
	}
}

func TestSignOutboundUnicast(t *testing.T) {
	t.Run("unlicensed text DM goes out under PKI, unsigned", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n, self := signingNode(t, mt, 0, &events)
		peer := newIdentity(t, 0x22)
		n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: peer.pub} })
		if err := n.SendText(context.Background(), peer.id, "dm"); err != nil {
			t.Fatal(err)
		}
		sent := mt.lastSent().packet
		data, err := crypto.TryDecodePKI(sent, self.pub, peer.priv)
		if err != nil {
			t.Fatalf("DM was not PKI-encrypted to the peer: %v", err)
		}
		if data.XeddsaSignature != nil {
			t.Error("PKI unicast carried a signature")
		}
	})

	t.Run("licensed text DM is signed", func(t *testing.T) {
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

	// A NodeInfo reply carries the key peers will use, so it is signed though unicast.
	t.Run("NodeInfo reply is signed", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n, self := signingNode(t, mt, 0, &events)
		req, _ := proto.Marshal(&pb.User{LongName: "Asker"})
		inject(n, mt, decodedPacket(0xAA, n.cfg.NodeID, 40, &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: req, WantResponse: true}))

		sent, data := decryptSent(t, mt)
		if data.Portnum != pb.PortNum_NODEINFO_APP || sent.To != 0xAA {
			t.Fatalf("last sent %v to %v, want a NodeInfo reply to !000000aa", data.Portnum, core.NodeID(sent.To))
		}
		if !crypto.VerifyPacketData(self.pub, sent.From, sent.Id, sent.To, data, data.XeddsaSignature) {
			t.Error("unicast NodeInfo reply was not signed")
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

	data := signedData(t, peer, 50, core.BroadcastNodeID, pb.PortNum_TEXT_MESSAGE_APP, []byte("verified"))
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

	data := signedData(t, peer, 51, core.BroadcastNodeID, pb.PortNum_TEXT_MESSAGE_APP, []byte("tampered"))
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
	data := signedData(t, peer, 60, core.BroadcastNodeID, pb.PortNum_NODEINFO_APP, userBytes)
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
	data := &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes}
	sig, err := crypto.SignPacketData(peer.priv, claimed.Uint32(), 61, core.BroadcastNodeID.Uint32(), data)
	if err != nil {
		t.Fatal(err)
	}
	data.XeddsaSignature = sig
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

// Only STRICT drops a packet for being unsigned (test_packet_signing A4, A6, A10).
func TestReceiveBalancedAcceptsUnsigned(t *testing.T) {
	for _, to := range []core.NodeID{core.BroadcastNodeID, 0} {
		mt := newMockTransport()
		var events []any
		n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_BALANCED, &events)
		if to == 0 {
			to = n.cfg.NodeID
		}
		signer := newIdentity(t, 0x44)
		n.NodeDB().Update(signer.id.Uint32(), func(info *pb.NodeInfo) {
			info.User = &pb.User{PublicKey: signer.pub}
			info.HasXeddsaSigned = true
		})
		data := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("unsigned")}
		inject(n, mt, decodedPacket(signer.id, to, 80, data))
		if len(textEvents(events)) != 1 {
			t.Errorf("to %v: unsigned packet from a known signer was dropped", to)
		}
	}
}

// STRICT exempts what cannot or need not be signed (test_packet_signing A13, A24,
// A25, A27).
func TestReceiveStrictExemptions(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT, &events)

	tests := []struct {
		portnum pb.PortNum
		pki     bool
	}{
		{pb.PortNum_ROUTING_APP, false},
		{pb.PortNum_TRACEROUTE_APP, false},
		{pb.PortNum_KEY_VERIFICATION_APP, false},
		{pb.PortNum_TEXT_MESSAGE_APP, true},
	}
	for _, tt := range tests {
		pkt := &pb.MeshPacket{Id: 1, From: 0xAA, To: n.cfg.NodeID.Uint32()}
		if _, ok := n.base.checkSignaturePolicy(pkt, &pb.Data{Portnum: tt.portnum}, tt.pki); !ok {
			t.Errorf("%v (pki=%v): STRICT dropped an exempt unsigned packet", tt.portnum, tt.pki)
		}
	}
}

// Every hop rewrites a traceroute, so a signature on one is ignored rather than
// verified (test_packet_signing A26).
func TestReceiveTracerouteSignatureIgnored(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT, &events)
	peer := newIdentity(t, 0x22)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: peer.pub} })

	data := signedData(t, peer, 55, n.cfg.NodeID, pb.PortNum_TRACEROUTE_APP, []byte{0x0a, 0x04, 1, 2, 3, 4})
	data.Payload = []byte{0x0a, 0x04, 9, 9, 9, 9} // rewritten by a relay
	pkt := &pb.MeshPacket{Id: 55, From: peer.id.Uint32(), To: n.cfg.NodeID.Uint32()}
	signed, ok := n.base.checkSignaturePolicy(pkt, data, false)
	if !ok || signed {
		t.Errorf("checkSignaturePolicy = signed %v, accept %v; want unsigned and accepted", signed, ok)
	}
}

// A NodeInfo signed by the held key must also carry that key (test_packet_signing
// A21, A23).
func TestReceiveSignedNodeInfoMustCarrySignerKey(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)
	peer := newIdentity(t, 0x22)
	other := newIdentity(t, 0x77)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) {
		info.User = &pb.User{LongName: "Peer", PublicKey: peer.pub}
	})

	swapped, _ := proto.Marshal(&pb.User{LongName: "Swapped", PublicKey: other.pub})
	// Checked directly too: on a bridge the verifying key can come from
	// PublicKeyForNode with nothing in the NodeDB for pinIdentity to compare.
	pkt := &pb.MeshPacket{Id: 56, From: peer.id.Uint32(), To: core.BroadcastNodeID.Uint32()}
	if _, ok := n.base.checkSignaturePolicy(pkt, signedData(t, peer, 56, core.BroadcastNodeID, pb.PortNum_NODEINFO_APP, swapped), false); ok {
		t.Error("checkSignaturePolicy accepted a signed NodeInfo advertising another key")
	}
	inject(n, mt, decodedPacket(peer.id, core.BroadcastNodeID, 56, signedData(t, peer, 56, core.BroadcastNodeID, pb.PortNum_NODEINFO_APP, swapped)))
	if info := n.NodeDB().Get(peer.id.Uint32()); info.User.LongName != "Peer" || string(info.User.PublicKey) != string(peer.pub) {
		t.Error("a signed NodeInfo advertising another key was applied")
	}

	consistent, _ := proto.Marshal(&pb.User{LongName: "Renamed", PublicKey: peer.pub})
	inject(n, mt, decodedPacket(peer.id, core.BroadcastNodeID, 57, signedData(t, peer, 57, core.BroadcastNodeID, pb.PortNum_NODEINFO_APP, consistent)))
	if info := n.NodeDB().Get(peer.id.Uint32()); info.User.LongName != "Renamed" {
		t.Error("a consistent signed NodeInfo was not applied")
	}
}

// Firmware's NodeDB::updateUser rules (test_packet_signing N1-N13 and
// test_nodedb_identity_hygiene).
func TestPinIdentity(t *testing.T) {
	held := newIdentity(t, 0x55)
	planted := newIdentity(t, 0x66)
	nodeInfo := func(u *pb.User) *pb.Data {
		b, _ := proto.Marshal(u)
		return &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: b}
	}
	setup := func(t *testing.T, policy pb.Config_SecurityConfig_PacketSignaturePolicy, signer bool) (*Node, *mockTransport, testIdentity) {
		mt := newMockTransport()
		var events []any
		n, self := signingNode(t, mt, policy, &events)
		n.NodeDB().Update(0xAA, func(info *pb.NodeInfo) {
			info.User = &pb.User{LongName: "Original", PublicKey: held.pub}
			info.HasXeddsaSigned = signer
		})
		return n, mt, self
	}
	longName := func(n *Node) string { return n.NodeDB().Get(0xAA).User.LongName }

	t.Run("a different key drops the whole NodeInfo", func(t *testing.T) {
		n, mt, _ := setup(t, 0, false)
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 90, nodeInfo(&pb.User{LongName: "Renamed", PublicKey: planted.pub})))
		if info := n.NodeDB().Get(0xAA); info.User.LongName != "Original" || string(info.User.PublicKey) != string(held.pub) {
			t.Error("a NodeInfo with a conflicting key was applied")
		}
	})

	t.Run("a keyless NodeInfo is dropped once a key is held", func(t *testing.T) {
		n, mt, _ := setup(t, 0, false)
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 91, nodeInfo(&pb.User{LongName: "Keyless"})))
		if longName(n) != "Original" {
			t.Error("a keyless NodeInfo was applied over a held key")
		}
	})

	t.Run("the matching key is applied", func(t *testing.T) {
		n, mt, _ := setup(t, 0, false)
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 92, nodeInfo(&pb.User{LongName: "Renamed", PublicKey: held.pub})))
		if longName(n) != "Renamed" {
			t.Error("a NodeInfo carrying the held key was refused")
		}
	})

	t.Run("COMPATIBLE accepts unsigned updates from a signer", func(t *testing.T) {
		n, mt, _ := setup(t, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_COMPATIBLE, true)
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 93, nodeInfo(&pb.User{LongName: "Renamed", PublicKey: held.pub})))
		if longName(n) != "Renamed" {
			t.Error("COMPATIBLE refused an unsigned update from a known signer")
		}
	})

	t.Run("BALANCED refuses unsigned updates from a signer", func(t *testing.T) {
		n, mt, _ := setup(t, pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_BALANCED, true)
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 94, nodeInfo(&pb.User{LongName: "Impostor", PublicKey: held.pub})))
		if longName(n) != "Original" {
			t.Error("BALANCED let an unsigned NodeInfo rewrite a known signer's identity")
		}
	})

	t.Run("a NodeInfo advertising our own key is refused", func(t *testing.T) {
		n, mt, self := setup(t, 0, false)
		inject(n, mt, decodedPacket(0xBB, core.BroadcastNodeID, 95, nodeInfo(&pb.User{LongName: "Clone", PublicKey: self.pub})))
		if n.NodeDB().Get(0xBB) != nil {
			t.Error("a NodeInfo carrying our own public key was stored")
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
