package node

import (
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

// sentRouting decodes the last packet sent as a Routing response.
func sentRouting(t *testing.T, mt *mockTransport) (*pb.MeshPacket, *pb.Data, pb.Routing_Error) {
	t.Helper()
	sent, data := decryptSent(t, mt)
	if data.Portnum != pb.PortNum_ROUTING_APP {
		t.Fatalf("last sent %v, want ROUTING_APP", data.Portnum)
	}
	r := &pb.Routing{}
	if err := proto.Unmarshal(data.Payload, r); err != nil {
		t.Fatal(err)
	}
	return sent, data, r.GetErrorReason()
}

func wantAckPacket(from, to core.NodeID, id uint32, data *pb.Data) transport.NetworkPacket {
	pkt := decodedPacket(from, to, id, data)
	pkt.Packet.WantAck = true
	pkt.Packet.HopStart, pkt.Packet.HopLimit = 3, 2
	return pkt
}

func TestResponseHopLimit(t *testing.T) {
	bf := &pb.Data{Bitfield: proto.Uint32(0)}
	tests := []struct {
		name               string
		hopStart, hopLimit uint32
		data               *pb.Data
		configured, want   uint32
	}{
		{"one hop used, margin of two", 3, 2, nil, 7, 3},
		{"margin capped at the limit", 7, 2, nil, 7, 7},
		{"more hops than the limit", 7, 0, nil, 3, 7},
		{"zero-hop request from a 2.5+ sender", 0, 0, bf, 3, 0},
		{"unknown hops", 0, 0, nil, 3, 3},
		{"invalid hop_start", 1, 3, nil, 3, 3},
	}
	for _, tt := range tests {
		pkt := &pb.MeshPacket{HopStart: tt.hopStart, HopLimit: tt.hopLimit}
		if got := responseHopLimit(pkt, tt.data, tt.configured); got != tt.want {
			t.Errorf("%s: responseHopLimit = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// Mirrors ReliableRouter::sniffReceived for packets addressed to us.
func TestNodeAcks(t *testing.T) {
	text := func() *pb.Data { return &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hi")} }

	t.Run("a text DM's ack wants an ack", func(t *testing.T) {
		mt := newMockTransport()
		n := newTestNode(t, mt)
		inject(n, mt, wantAckPacket(0xAA, n.cfg.NodeID, 10, text()))
		sent, data, reason := sentRouting(t, mt)
		if reason != pb.Routing_NONE || data.RequestId != 10 || sent.To != 0xAA || !sent.WantAck {
			t.Errorf("ack: reason %v, request %d, to %v, want_ack %v", reason, data.RequestId, core.NodeID(sent.To), sent.WantAck)
		}
		if sent.HopLimit != 3 {
			t.Errorf("hop limit %d, want 3 (one hop used plus two)", sent.HopLimit)
		}
	})

	t.Run("other packets get a plain ack", func(t *testing.T) {
		mt := newMockTransport()
		n := newTestNode(t, mt)
		inject(n, mt, wantAckPacket(0xAA, n.cfg.NodeID, 11, &pb.Data{Portnum: pb.PortNum_PRIVATE_APP}))
		if sent, _, _ := sentRouting(t, mt); sent.WantAck {
			t.Error("a non-text ack wanted an ack")
		}
	})

	t.Run("no ack without want_ack, or for others", func(t *testing.T) {
		mt := newMockTransport()
		n := newTestNode(t, mt)
		inject(n, mt, decodedPacket(0xAA, n.cfg.NodeID, 12, text()))
		inject(n, mt, wantAckPacket(0xAA, core.BroadcastNodeID, 13, text()))
		inject(n, mt, wantAckPacket(0xAA, 0xBB, 14, text()))
		if mt.sentCount() != 0 {
			t.Errorf("sent %d acks, want none", mt.sentCount())
		}
	})

	t.Run("a reply replaces the ack", func(t *testing.T) {
		mt := newMockTransport()
		n := newTestNode(t, mt)
		inject(n, mt, wantAckPacket(0xAA, n.cfg.NodeID, 15, nodeInfoRequest()))
		if mt.sentCount() != 1 {
			t.Fatalf("sent %d packets, want only the NodeInfo reply", mt.sentCount())
		}
		if _, data := decryptSent(t, mt); data.Portnum != pb.PortNum_NODEINFO_APP {
			t.Errorf("sent %v, want the NodeInfo reply", data.Portnum)
		}
	})
}

func TestNodeNaksUndecodable(t *testing.T) {
	t.Run("unknown channel", func(t *testing.T) {
		mt := newMockTransport()
		n := newTestNode(t, mt)
		pkt := pskPacket(t, n, 0xAA, n.cfg.NodeID, 20, &pb.Data{Portnum: pb.PortNum_PRIVATE_APP})
		pkt.Packet.Channel ^= 0xFF
		pkt.Packet.WantAck = true
		inject(n, mt, pkt)
		if _, data, reason := sentRouting(t, mt); reason != pb.Routing_NO_CHANNEL || data.RequestId != 20 {
			t.Errorf("nak reason %v for request %d, want NO_CHANNEL for 20", reason, data.RequestId)
		}
	})

	t.Run("PKI from a node whose key we lack", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n, _ := signingNode(t, mt, 0, &events)
		inject(n, mt, transport.NetworkPacket{Packet: &pb.MeshPacket{
			Id: 21, From: 0xAA, To: n.cfg.NodeID.Uint32(), WantAck: true,
			PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: make([]byte, 40)},
		}})
		if _, _, reason := sentRouting(t, mt); reason != pb.Routing_PKI_UNKNOWN_PUBKEY {
			t.Errorf("nak reason %v, want PKI_UNKNOWN_PUBKEY", reason)
		}
	})
}

// A peer that cannot decrypt our PKI packet asks for our key with a nak.
func TestNodeAnswersUnknownPubkeyWithNodeInfo(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, self := signingNode(t, mt, 0, &events)
	nak, _ := proto.Marshal(&pb.Routing{Variant: &pb.Routing_ErrorReason{ErrorReason: pb.Routing_PKI_UNKNOWN_PUBKEY}})
	inject(n, mt, decodedPacket(0xAA, n.cfg.NodeID, 30, &pb.Data{Portnum: pb.PortNum_ROUTING_APP, Payload: nak, RequestId: 5}))

	sent, data := decryptSent(t, mt)
	if data.Portnum != pb.PortNum_NODEINFO_APP || sent.To != 0xAA {
		t.Fatalf("sent %v to %v, want our NodeInfo to !000000aa", data.Portnum, core.NodeID(sent.To))
	}
	user := &pb.User{}
	if err := proto.Unmarshal(data.Payload, user); err != nil || string(user.PublicKey) != string(self.pub) {
		t.Error("NodeInfo did not carry our public key")
	}
}

func TestBridgeAcks(t *testing.T) {
	const managed = core.NodeID(0xBEEF)
	bridge := func(t *testing.T, mt *mockTransport, manual bool) *BridgeNode {
		return newTestBridge(t, mt, func(c *BridgeConfig) {
			c.IsManagedNode = func(id core.NodeID) bool { return id == c.NodeID || id == managed }
			c.ManualAcks = manual
		})
	}
	text := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hi")}

	t.Run("acks as the addressed identity", func(t *testing.T) {
		mt := newMockTransport()
		b := bridge(t, mt, false)
		b.handleIncomingPacket(wantAckPacket(0xAA, managed, 40, text))
		if sent, _, reason := sentRouting(t, mt); core.NodeID(sent.From) != managed || reason != pb.Routing_NONE {
			t.Errorf("ack from %v with %v, want NONE from %v", core.NodeID(sent.From), reason, managed)
		}
	})

	t.Run("ManualAcks leaves acks to the consumer", func(t *testing.T) {
		mt := newMockTransport()
		b := bridge(t, mt, true)
		b.handleIncomingPacket(wantAckPacket(0xAA, managed, 41, text))
		if mt.sentCount() != 0 {
			t.Errorf("sent %d packets with ManualAcks", mt.sentCount())
		}
	})

	t.Run("a traceroute reply replaces the ack", func(t *testing.T) {
		mt := newMockTransport()
		b := bridge(t, mt, false)
		rd, _ := proto.Marshal(&pb.RouteDiscovery{})
		b.handleIncomingPacket(wantAckPacket(0xAA, managed, 42, &pb.Data{Portnum: pb.PortNum_TRACEROUTE_APP, Payload: rd, WantResponse: true}))
		if mt.sentCount() != 1 {
			t.Fatalf("sent %d packets, want only the traceroute reply", mt.sentCount())
		}
		if _, data := decryptSent(t, mt); data.Portnum != pb.PortNum_TRACEROUTE_APP {
			t.Errorf("sent %v, want the traceroute reply", data.Portnum)
		}
	})
}
