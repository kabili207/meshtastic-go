package node

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
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

// The bridge send path resolves its channel separately from base.sendPacket, so it
// needs its own check that a unicast follows the channel a node was last heard on.
func TestBridgeDMUsesChannelNodeInfoArrivedOn(t *testing.T) {
	mt := newMockTransport()
	secondKey := make([]byte, 16)
	copy(secondKey, crypto.DefaultKey)
	secondKey[15] = 0x42
	b := newTestBridge(t, mt, func(cfg *BridgeConfig) {
		cfg.Channels = &pb.ChannelSet{
			Settings: []*pb.ChannelSettings{
				{Name: "LongFast", Psk: crypto.DefaultKey},
				{Name: "SecondCh", Psk: secondKey},
			},
		}
	})

	userBytes, _ := proto.Marshal(&pb.User{LongName: "Peer"})
	b.handleIncomingPacket(transport.NetworkPacket{
		Channel: "SecondCh",
		Packet: &pb.MeshPacket{
			Id:   7,
			From: 0xAA,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes},
			},
		},
	})

	if info := b.db.Get(0xAA); info == nil || info.Channel != 1 {
		t.Fatalf("nodedb channel index = %v, want 1", info)
	}

	if _, err := b.SendReactionAs(context.Background(), b.cfg.NodeID, 0xAA, 7, "👍"); err != nil {
		t.Fatal(err)
	}
	if got := mt.lastSent().channel; got != "SecondCh" {
		t.Errorf("DM went out on %q, want SecondCh", got)
	}
}

// Channels the bridge joins after construction must be indexed as well, since a
// bridge learns most of its channels from portals at runtime.
func TestBridgeRuntimeChannelTrackedForUnicast(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt)
	if err := b.AddChannel("Later", "AQ=="); err != nil {
		t.Fatal(err)
	}
	if err := b.AddChannel("Later", "AQ=="); err != nil {
		t.Fatal(err)
	}
	if len(b.base.channelNames) != 2 {
		t.Fatalf("channelNames = %v, want primary plus one", b.base.channelNames)
	}

	userBytes, _ := proto.Marshal(&pb.User{LongName: "Peer"})
	b.handleIncomingPacket(transport.NetworkPacket{
		Channel: "Later",
		Packet: &pb.MeshPacket{
			Id:   8,
			From: 0xBB,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{Portnum: pb.PortNum_NODEINFO_APP, Payload: userBytes},
			},
		},
	})
	if _, err := b.SendTextAs(context.Background(), b.cfg.NodeID, 0xBB, "hi"); err != nil {
		t.Fatal(err)
	}
	if got := mt.lastSent().channel; got != "Later" {
		t.Errorf("DM went out on %q, want Later", got)
	}
}

func TestBridgeSetNodeChannelSeedsUnicastRouting(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt)
	if err := b.AddChannel("Shared", "AQ=="); err != nil {
		t.Fatal(err)
	}
	if b.SetNodeChannel(0xCC, "NotRegistered") {
		t.Error("SetNodeChannel accepted an unregistered channel")
	}
	if !b.SetNodeChannel(0xCC, "Shared") {
		t.Fatal("SetNodeChannel rejected a registered channel")
	}
	if _, err := b.SendTextAs(context.Background(), b.cfg.NodeID, 0xCC, "hi"); err != nil {
		t.Fatal(err)
	}
	if got := mt.lastSent().channel; got != "Shared" {
		t.Errorf("DM went out on %q, want Shared", got)
	}
}

// A NodeInfo whose key does not derive its node ID is refused rather than sent,
// since 2.8 peers drop it on first contact anyway.
func TestBridgeRefusesNodeInfoWithMismatchedIdentity(t *testing.T) {
	pub, _, _ := crypto.KeyPairFromSeed(bytes.Repeat([]byte{0x11}, 32))
	derived, _ := core.NodeIDFromPublicKey(pub)
	keyFor := func(id core.NodeID) []byte { return pub }

	mismatched := newTestBridge(t, newMockTransport(), func(cfg *BridgeConfig) {
		cfg.PublicKeyForNode = keyFor
	})
	if _, err := mismatched.SendNodeInfoAs(context.Background(), mismatched.cfg.NodeID, core.BroadcastNodeID); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("err = %v, want ErrIdentityMismatch", err)
	}

	mt := newMockTransport()
	matched := newTestBridge(t, mt, func(cfg *BridgeConfig) {
		cfg.NodeID = derived
		cfg.IsManagedNode = func(id core.NodeID) bool { return id == derived }
		cfg.PublicKeyForNode = keyFor
	})
	if _, err := matched.SendNodeInfoAs(context.Background(), derived, core.BroadcastNodeID); err != nil {
		t.Fatalf("matched identity refused: %v", err)
	}
	if mt.sentCount() != 1 {
		t.Fatalf("sent %d packets, want 1", mt.sentCount())
	}
}
