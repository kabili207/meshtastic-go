package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

// A text DM from a peer whose key we hold gets an ack the peer can verify.
func TestAckCarriesProof(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, self := signingNode(t, mt, 0, &events)
	peer := newIdentity(t, 0x22)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: peer.pub} })

	inject(n, mt, wantAckPacket(peer.id, n.cfg.NodeID, 10, &pb.Data{Portnum: pb.PortNum_PRIVATE_APP}))
	sent, data, _ := sentRouting(t, mt)
	got := crypto.VerifyAckProof(data.Payload, peer.priv, self.pub, sent.From, sent.To, data.RequestId)
	if got != pb.MeshPacket_ACK_PROOF_VALID {
		t.Errorf("peer's verdict on our ack: %v, want VALID", got)
	}
}

func TestAckWithoutPeerKeyHasNoProof(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)
	inject(n, mt, wantAckPacket(0xAA, n.cfg.NodeID, 11, &pb.Data{Portnum: pb.PortNum_PRIVATE_APP}))
	if _, data, _ := sentRouting(t, mt); crypto.HasAckProof(data.Payload) {
		t.Error("an ack to a node whose key we lack carried a proof")
	}
}

// Received acks are judged, and only our own verdict is reported.
func TestReceivedAckProofVerdict(t *testing.T) {
	routing, _ := proto.Marshal(&pb.Routing{Variant: &pb.Routing_ErrorReason{ErrorReason: pb.Routing_NONE}})

	setup := func(t *testing.T) (*Node, *mockTransport, testIdentity, testIdentity, *[]*event.RoutingReceived) {
		mt := newMockTransport()
		var events []any
		n, self := signingNode(t, mt, 0, &events)
		peer := newIdentity(t, 0x22)
		n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: peer.pub} })
		var acks []*event.RoutingReceived
		n.OnEvent(func(evt any) {
			if r, ok := evt.(*event.RoutingReceived); ok {
				acks = append(acks, r)
			}
		})
		return n, mt, self, peer, &acks
	}

	t.Run("valid proof", func(t *testing.T) {
		n, mt, self, peer, acks := setup(t)
		proven, _ := crypto.AttachAckProof(routing, peer.priv, self.pub, peer.id.Uint32(), n.cfg.NodeID.Uint32(), 77)
		inject(n, mt, decodedPacket(peer.id, n.cfg.NodeID, 20, &pb.Data{Portnum: pb.PortNum_ROUTING_APP, Payload: proven, RequestId: 77}))
		if len(*acks) != 1 || (*acks)[0].AckProof != pb.MeshPacket_ACK_PROOF_VALID {
			t.Errorf("events %+v, want one VALID ack", *acks)
		}
	})

	t.Run("claimed status is not trusted", func(t *testing.T) {
		n, mt, _, peer, acks := setup(t)
		pkt := decodedPacket(peer.id, n.cfg.NodeID, 21, &pb.Data{Portnum: pb.PortNum_ROUTING_APP, Payload: routing, RequestId: 77})
		pkt.Packet.AckProofStatus = pb.MeshPacket_ACK_PROOF_VALID
		inject(n, mt, pkt)
		if len(*acks) != 1 || (*acks)[0].AckProof != pb.MeshPacket_ACK_PROOF_ABSENT || pkt.Packet.AckProofStatus != pb.MeshPacket_ACK_PROOF_ABSENT {
			t.Errorf("an inbound VALID claim survived: %+v", *acks)
		}
	})

	t.Run("proof from someone else", func(t *testing.T) {
		n, mt, self, peer, acks := setup(t)
		other := newIdentity(t, 0x44)
		forged, _ := crypto.AttachAckProof(routing, other.priv, self.pub, peer.id.Uint32(), n.cfg.NodeID.Uint32(), 77)
		inject(n, mt, decodedPacket(peer.id, n.cfg.NodeID, 22, &pb.Data{Portnum: pb.PortNum_ROUTING_APP, Payload: forged, RequestId: 77}))
		if len(*acks) != 1 || (*acks)[0].AckProof != pb.MeshPacket_ACK_PROOF_INVALID {
			t.Errorf("events %+v, want one INVALID ack", *acks)
		}
	})
}

// Bridge acks, automatic and manual, are proven from the managed identity.
func TestBridgeAcksCarryProof(t *testing.T) {
	self := newIdentity(t, 0x11)
	peer := newIdentity(t, 0x22)
	mt := newMockTransport()
	b := newTestBridge(t, mt, func(c *BridgeConfig) {
		c.NodeID = self.id
		c.IsManagedNode = func(id core.NodeID) bool { return id == self.id }
		c.PrivateKeyForNode = func(id core.NodeID) []byte {
			if id == self.id {
				return self.priv
			}
			return nil
		}
		c.PublicKeyForNode = func(id core.NodeID) []byte {
			if id == peer.id {
				return peer.pub
			}
			return nil
		}
	})

	b.handleIncomingPacket(wantAckPacket(peer.id, self.id, 30, &pb.Data{Portnum: pb.PortNum_PRIVATE_APP}))
	sent, data, _ := sentRouting(t, mt)
	if crypto.VerifyAckProof(data.Payload, peer.priv, self.pub, sent.From, sent.To, data.RequestId) != pb.MeshPacket_ACK_PROOF_VALID {
		t.Error("automatic bridge ack was not proven")
	}

	if err := b.SendAckAs(context.Background(), self.id, peer.id, 31); err != nil {
		t.Fatal(err)
	}
	sent, data, _ = sentRouting(t, mt)
	if crypto.VerifyAckProof(data.Payload, peer.priv, self.pub, sent.From, sent.To, data.RequestId) != pb.MeshPacket_ACK_PROOF_VALID {
		t.Error("SendAckAs was not proven")
	}
}

// The verdict reaches the app on the delivered packet, which is how firmware
// lets the app show an ack as verified.
func TestAppSeesAckProofVerdict(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, self := signingNode(t, mt, 0, &events)
	peer := newIdentity(t, 0x22)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: peer.pub} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := stream.NewRadioConn(n.Conn(ctx))
	defer app.Close()
	if err := app.Write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_WantConfigId{WantConfigId: 1}}); err != nil {
		t.Fatal(err)
	}
	for appRead(t, app).GetConfigCompleteId() != 1 {
	}

	routing, _ := proto.Marshal(&pb.Routing{Variant: &pb.Routing_ErrorReason{ErrorReason: pb.Routing_NONE}})
	proven, _ := crypto.AttachAckProof(routing, peer.priv, self.pub, peer.id.Uint32(), n.cfg.NodeID.Uint32(), 77)
	inject(n, mt, decodedPacket(peer.id, n.cfg.NodeID, 20, &pb.Data{Portnum: pb.PortNum_ROUTING_APP, Payload: proven, RequestId: 77}))

	if got := appRead(t, app).GetPacket().GetAckProofStatus(); got != pb.MeshPacket_ACK_PROOF_VALID {
		t.Errorf("app saw %v, want VALID", got)
	}
}
