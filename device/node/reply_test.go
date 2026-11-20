package node

import (
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

func positionRequest() *pb.Data {
	return &pb.Data{Portnum: pb.PortNum_POSITION_APP, WantResponse: true}
}

func nodeInfoRequest() *pb.Data {
	user, _ := proto.Marshal(&pb.User{LongName: "Asker"})
	return &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: user, WantResponse: true}
}

// Firmware's MeshModule only answers broadcasts and requests addressed to it, so
// an overheard request between two other nodes must not draw a reply.
func TestNoReplyToOverheardRequests(t *testing.T) {
	for _, req := range []*pb.Data{positionRequest(), nodeInfoRequest()} {
		mt := newMockTransport()
		n := newTestNode(t, mt)
		inject(n, mt, decodedPacket(0xAA, 0xBB, 1, req))
		if mt.sentCount() != 0 {
			t.Errorf("%v: replied to a request addressed to another node", req.Portnum)
		}
		inject(n, mt, decodedPacket(0xAA, n.cfg.NodeID, 2, req))
		if mt.sentCount() != 1 {
			t.Errorf("%v: did not reply to a request addressed to us", req.Portnum)
		}
	}
}

// Firmware sends at most one position reply per 3 minutes, whoever asks.
func TestPositionRepliesThrottledAcrossRequesters(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)
	for i, from := range []core.NodeID{0xAA, 0xBB, 0xCC} {
		inject(n, mt, decodedPacket(from, n.cfg.NodeID, uint32(10+i), positionRequest()))
	}
	if mt.sentCount() != 1 {
		t.Errorf("sent %d position replies to three requesters, want 1", mt.sentCount())
	}
}

// Each bridge identity answers only what is addressed to it, and the bridge
// itself answers broadcasts, so one request draws at most one reply.
func TestBridgeNodeInfoRepliesFromAddressedIdentity(t *testing.T) {
	const managed = core.NodeID(0xBEEF)
	tests := []struct {
		name   string
		to     core.NodeID
		wantAs core.NodeID // 0 means no reply
	}{
		{"broadcast", core.BroadcastNodeID, 0x12345678},
		{"to the bridge", 0x12345678, 0x12345678},
		{"to a managed node", managed, managed},
		{"between other nodes", 0xBB, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mt := newMockTransport()
			b := newTestBridge(t, mt, func(c *BridgeConfig) {
				c.IsManagedNode = func(id core.NodeID) bool { return id == c.NodeID || id == managed }
				c.NodeInfoForNode = func(id core.NodeID) (string, string, []byte, bool) {
					return "Managed", "MGD", nil, id == managed
				}
			})
			b.handleIncomingPacket(decodedPacket(0xAA, tt.to, 1, nodeInfoRequest()))

			if tt.wantAs == 0 {
				if mt.sentCount() != 0 {
					t.Errorf("sent %d replies to an overheard request", mt.sentCount())
				}
				return
			}
			if mt.sentCount() != 1 {
				t.Fatalf("sent %d replies, want 1", mt.sentCount())
			}
			if from := core.NodeID(mt.lastSent().packet.From); from != tt.wantAs {
				t.Errorf("replied as %v, want %v", from, tt.wantAs)
			}
		})
	}
}
