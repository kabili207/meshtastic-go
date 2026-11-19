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

func sentBitfield(t *testing.T, mt *mockTransport) uint32 {
	t.Helper()
	data, err := decryptWith(mt.lastSent().packet, crypto.DefaultKey)
	if err != nil {
		t.Fatalf("decrypting sent packet: %v", err)
	}
	return data.GetBitfield()
}

func TestBridgeSendTextAsAutomationBit(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt)

	if _, err := b.SendTextAs(context.Background(), b.cfg.NodeID, core.BroadcastNodeID, "human"); err != nil {
		t.Fatal(err)
	}
	if bf := sentBitfield(t, mt); bf&bitfieldIsAutomation != 0 {
		t.Errorf("bitfield = %#x, automation bit set without WithAutomation", bf)
	}

	if _, err := b.SendTextAs(context.Background(), b.cfg.NodeID, core.BroadcastNodeID, "bot", WithAutomation()); err != nil {
		t.Fatal(err)
	}
	if bf := sentBitfield(t, mt); bf != bitfieldOkToMQTT|bitfieldIsAutomation {
		t.Errorf("bitfield = %#x, want ok_to_mqtt|is_automation", bf)
	}
}

func TestNodeSendTextAutomationBit(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)

	if err := n.SendText(context.Background(), core.BroadcastNodeID, "bot", WithAutomation()); err != nil {
		t.Fatal(err)
	}
	if bf := sentBitfield(t, mt); bf&bitfieldIsAutomation == 0 {
		t.Errorf("bitfield = %#x, automation bit missing", bf)
	}
}

func TestReceivedAutomationBitSurfacesOnEvent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bitfield uint32
		want     bool
	}{
		{"flagged", bitfieldOkToMQTT | bitfieldIsAutomation, true},
		{"unflagged", bitfieldOkToMQTT, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newTestBridge(t, newMockTransport())
			var got *event.TextMessage
			b.OnEvent(func(evt any) {
				if e, ok := evt.(*event.TextMessage); ok {
					got = e
				}
			})

			bf := tc.bitfield
			raw, _ := proto.Marshal(&pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hi"), Bitfield: &bf})
			enc, _ := crypto.XOR(raw, crypto.DefaultKey, 91, 0xBB)
			b.handleIncomingPacket(transport.NetworkPacket{Packet: &pb.MeshPacket{
				Id: 91, From: 0xBB, To: core.BroadcastNodeID.Uint32(),
				Channel:        core.NewChannelWithKey("LongFast", crypto.DefaultKey).GetHash(),
				PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: enc},
			}})

			if got == nil {
				t.Fatal("no TextMessage event")
			}
			if got.IsAutomation != tc.want {
				t.Errorf("IsAutomation = %v, want %v", got.IsAutomation, tc.want)
			}
		})
	}
}
