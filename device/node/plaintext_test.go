package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"google.golang.org/protobuf/proto"
)

// PSK 0x00 turns encryption off. Firmware still sends the payload in the
// encrypted field, just unencrypted, and reads it back the same way.
func TestPlaintextChannelRoundTrip(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n := newTestNode(t, mt, func(c *Config) {
		c.Channels = &pb.ChannelSet{Settings: []*pb.ChannelSettings{{Name: "Open", Psk: []byte{0}}}}
		c.EventHandlers = []event.Handler{func(evt any) { events = append(events, evt) }}
	})

	if err := n.SendText(context.Background(), core.BroadcastNodeID, "in the clear"); err != nil {
		t.Fatal(err)
	}
	data := &pb.Data{}
	if err := proto.Unmarshal(mt.lastSent().packet.GetEncrypted(), data); err != nil || string(data.Payload) != "in the clear" {
		t.Fatalf("sent payload is not plaintext Data: %v", err)
	}

	inject(n, mt, pskPacket(t, n, 0xAA, core.BroadcastNodeID, 50, &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hello")}))
	if msgs := textEvents(events); len(msgs) != 1 || msgs[0].Message != "hello" {
		t.Errorf("received %d text events from a plaintext channel, want 1", len(msgs))
	}
}
