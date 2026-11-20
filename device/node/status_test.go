package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"google.golang.org/protobuf/proto"
)

func statusPacket(status string) *pb.Data {
	payload, _ := proto.Marshal(&pb.StatusMessage{Status: status})
	return &pb.Data{Portnum: pb.PortNum_NODE_STATUS_APP, Payload: payload}
}

// Like firmware's StatusMessage module, a status goes out as a background
// broadcast.
func TestSendStatus(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)
	if err := n.SendStatus(context.Background(), "out hiking"); err != nil {
		t.Fatal(err)
	}
	sent, data := decryptSent(t, mt)
	if data.Portnum != pb.PortNum_NODE_STATUS_APP || !core.NodeID(sent.To).IsBroadcast() || sent.Priority != pb.MeshPacket_BACKGROUND {
		t.Errorf("sent %v to %v at %v, want a background status broadcast", data.Portnum, core.NodeID(sent.To), sent.Priority)
	}
	status := &pb.StatusMessage{}
	if err := proto.Unmarshal(data.Payload, status); err != nil || status.Status != "out hiking" {
		t.Errorf("status payload %q, %v", status.Status, err)
	}
}

// Firmware's buffer is 80 bytes including the terminator.
func TestSendStatusLimit(t *testing.T) {
	n := newTestNode(t, newMockTransport())
	if err := n.SendStatus(context.Background(), strings.Repeat("x", 79)); err != nil {
		t.Errorf("79 bytes refused: %v", err)
	}
	if err := n.SendStatus(context.Background(), strings.Repeat("x", 80)); err == nil {
		t.Error("80 bytes accepted")
	}
}

func TestReceiveStatus(t *testing.T) {
	t.Run("node", func(t *testing.T) {
		mt := newMockTransport()
		var got *event.StatusMessageReceived
		n := newTestNode(t, mt, func(c *Config) {
			c.EventHandlers = []event.Handler{func(evt any) {
				if s, ok := evt.(*event.StatusMessageReceived); ok {
					got = s
				}
			}}
		})
		inject(n, mt, decodedPacket(0xAA, core.BroadcastNodeID, 1, statusPacket("on call")))
		if got == nil || got.Status != "on call" || got.From != 0xAA {
			t.Fatalf("event %+v", got)
		}
		if s, ok := n.NodeDB().Status(0xAA); !ok || s != "on call" {
			t.Errorf("NodeDB status %q, %v", s, ok)
		}
	})

	t.Run("bridge", func(t *testing.T) {
		b := newTestBridge(t, newMockTransport())
		var got *event.StatusMessageReceived
		b.OnEvent(func(evt any) {
			if s, ok := evt.(*event.StatusMessageReceived); ok {
				got = s
			}
		})
		b.handleIncomingPacket(decodedPacket(0xAA, core.BroadcastNodeID, 1, statusPacket("away")))
		if got == nil || got.Status != "away" {
			t.Fatalf("event %+v", got)
		}
		if s, _ := b.NodeDB().Status(0xAA); s != "away" {
			t.Errorf("NodeDB status %q", s)
		}
	})
}

func TestBridgeSendStatusAs(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt)
	if _, err := b.SendStatusAs(context.Background(), b.cfg.NodeID, "bridging"); err != nil {
		t.Fatal(err)
	}
	_, data := decryptSent(t, mt)
	status := &pb.StatusMessage{}
	if data.Portnum != pb.PortNum_NODE_STATUS_APP || proto.Unmarshal(data.Payload, status) != nil || status.Status != "bridging" {
		t.Errorf("sent %v %q", data.Portnum, status.Status)
	}
	if _, err := b.SendStatusAs(context.Background(), b.cfg.NodeID, strings.Repeat("x", 80)); err == nil {
		t.Error("80 bytes accepted")
	}
}

// Firmware rebroadcasts a configured status every 12 hours.
func TestStatusInterval(t *testing.T) {
	if statusInterval("") != 0 {
		t.Error("an empty status was scheduled")
	}
	if statusInterval("hi") != 12*time.Hour {
		t.Error("a status was not scheduled every 12 hours")
	}
}
