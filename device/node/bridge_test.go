package node

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
)

func newTestBridge(t *testing.T, mt *mockTransport, opts ...func(*BridgeConfig)) *BridgeNode {
	t.Helper()
	cfg := BridgeConfig{
		Transport:     mt,
		NodeID:        core.NodeID(0x12345678),
		Channels:      defaultChannels(),
		IsManagedNode: func(id core.NodeID) bool { return id == core.NodeID(0x12345678) },
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	b, err := NewBridge(cfg)
	if err != nil {
		t.Fatalf("NewBridge() error: %v", err)
	}
	return b
}

func TestBridgeNodeInfoIncludesOwnPublicKey(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 32)
	b := newTestBridge(t, newMockTransport(), func(cfg *BridgeConfig) {
		cfg.PublicKeyForNode = func(id core.NodeID) []byte {
			if id == cfg.NodeID {
				return want
			}
			return nil
		}
	})
	user := b.buildUserFor(b.cfg.NodeID)
	if user == nil {
		t.Fatal("buildUserFor returned nil for the bridge")
	}
	if !bytes.Equal(user.PublicKey, want) {
		t.Errorf("PublicKey = %x, want %x", user.PublicKey, want)
	}
}

// A decoded packet carries a channel index, not a hash, so the transport's channel
// name must win and the registered key must be attached.
func TestBridgeDecodedPacketUsesTransportChannel(t *testing.T) {
	b := newTestBridge(t, newMockTransport())
	var got *event.TextMessage
	b.OnEvent(func(evt any) {
		if tm, ok := evt.(*event.TextMessage); ok {
			got = tm
		}
	})

	b.handleIncomingPacket(transport.NetworkPacket{
		Channel: "LongFast",
		Source:  transport.PacketSourceMQTT,
		Packet: &pb.MeshPacket{
			From:    0xAAAA,
			To:      core.BroadcastNodeID.Uint32(),
			Id:      7,
			Channel: 0, // channel index on the uplinking gateway
			PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{
				Portnum: pb.PortNum_TEXT_MESSAGE_APP,
				Payload: []byte("hi"),
			}},
		},
	})

	if got == nil {
		t.Fatal("no TextMessage event emitted")
	}
	if got.ChannelName != "LongFast" {
		t.Errorf("ChannelName = %q, want LongFast", got.ChannelName)
	}
	if got.ChannelKey == nil || *got.ChannelKey != "AQ==" {
		t.Errorf("ChannelKey = %v, want AQ==", got.ChannelKey)
	}
}
