package node

import (
	"context"
	"errors"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

// A channel is identified by name and key together. These tests cover the cases
// where the name alone is not enough: two channels sharing a name, and two
// channels sharing the one-byte wire hash.

func otherKey() []byte {
	k := make([]byte, len(crypto.DefaultKey))
	copy(k, crypto.DefaultKey)
	k[15] ^= 0x42
	return k
}

// sharedNameChannels is a channel set with two channels named Shared that
// differ only in key.
func sharedNameChannels() *pb.ChannelSet {
	return &pb.ChannelSet{Settings: []*pb.ChannelSettings{
		{Name: "LongFast", Psk: crypto.DefaultKey},
		{Name: "Shared", Psk: crypto.DefaultKey},
		{Name: "Shared", Psk: otherKey()},
	}}
}

func decryptWith(pkt *pb.MeshPacket, key []byte) (*pb.Data, error) {
	return crypto.TryDecode(pkt, key)
}

func TestSendAmbiguousChannelNameErrors(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt, func(c *Config) { c.Channels = sharedNameChannels() })

	err := n.SendText(context.Background(), core.BroadcastNodeID, "hi", WithChannel("Shared"))
	if !errors.Is(err, core.ErrChannelAmbiguous) {
		t.Errorf("send on a shared name: err = %v, want ErrChannelAmbiguous", err)
	}
	err = n.SendText(context.Background(), core.BroadcastNodeID, "hi", WithChannel("Nope"))
	if !errors.Is(err, core.ErrChannelNotFound) {
		t.Errorf("send on an unknown name: err = %v, want ErrChannelNotFound", err)
	}
	if mt.sentCount() != 0 {
		t.Errorf("%d packets were sent despite the errors", mt.sentCount())
	}
}

func TestSendWithChannelDefPicksTheRightKey(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt, func(c *Config) { c.Channels = sharedNameChannels() })
	sharedB := core.NewChannelWithKey("Shared", otherKey())

	if err := n.SendText(context.Background(), core.BroadcastNodeID, "for B", WithChannelDef(sharedB)); err != nil {
		t.Fatal(err)
	}
	sent := mt.lastSent()
	if sent.channel != "Shared" {
		t.Errorf("transport channel = %q, want Shared", sent.channel)
	}
	if sent.packet.Channel != sharedB.GetHash() {
		t.Errorf("wire hash = %#x, want %#x", sent.packet.Channel, sharedB.GetHash())
	}
	data, err := decryptWith(sent.packet, otherKey())
	if err != nil || data.Portnum != pb.PortNum_TEXT_MESSAGE_APP || string(data.Payload) != "for B" {
		t.Errorf("packet did not decrypt with the selected key: data=%v err=%v", data, err)
	}
	if data, err := decryptWith(sent.packet, crypto.DefaultKey); err == nil && data.Portnum == pb.PortNum_TEXT_MESSAGE_APP && string(data.Payload) == "for B" {
		t.Error("packet also decrypts with the other same-name channel's key")
	}
}

// Two channels whose one-byte hashes collide must both stay receivable: the
// pipeline tries each registered channel with that hash, like firmware does.
func TestReceiveTriesEveryChannelWithSameHash(t *testing.T) {
	keyA := crypto.DefaultKey
	keyB := make([]byte, len(keyA))
	copy(keyB, keyA)
	keyB[0], keyB[1] = keyB[1], keyB[0] // same XOR, different key

	chA := core.NewChannelWithKey("ab", keyA)
	chB := core.NewChannelWithKey("ba", keyB) // same XOR of name bytes too
	if chA.GetHash() != chB.GetHash() {
		t.Fatalf("test setup: hashes differ (%#x, %#x)", chA.GetHash(), chB.GetHash())
	}

	for _, tc := range []struct {
		name string
		key  []byte
		want string
	}{
		{"first registered", keyA, "ab"},
		{"second registered", keyB, "ba"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mt := newMockTransport()
			var got *event.TextMessage
			n := newTestNode(t, mt, func(c *Config) {
				c.Channels = &pb.ChannelSet{Settings: []*pb.ChannelSettings{
					{Name: "ab", Psk: keyA},
					{Name: "ba", Psk: keyB},
				}}
				c.EventHandlers = []event.Handler{func(evt any) {
					if e, ok := evt.(*event.TextMessage); ok {
						got = e
					}
				}}
			})

			dataBytes, _ := proto.Marshal(&pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("collide")})
			encrypted, _ := crypto.XOR(dataBytes, tc.key, 77, 0xBB)
			inject(n, mt, transport.NetworkPacket{Packet: &pb.MeshPacket{
				Id: 77, From: 0xBB, To: core.BroadcastNodeID.Uint32(),
				Channel:        chA.GetHash(),
				PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: encrypted},
			}})

			if got == nil {
				t.Fatal("no event for a packet on a colliding hash")
			}
			if got.Channel == nil || got.Channel.GetName() != tc.want {
				t.Errorf("event channel = %v, want %s", got.Channel, tc.want)
			}
			if got.Message != "collide" {
				t.Errorf("message = %q", got.Message)
			}
		})
	}
}

func TestBridgeSetNodeChannelDistinguishesSameName(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt, func(cfg *BridgeConfig) { cfg.Channels = sharedNameChannels() })
	sharedB := core.NewChannelWithKey("Shared", otherKey())

	if !b.SetNodeChannel(0xCC, sharedB) {
		t.Fatal("SetNodeChannel rejected a registered channel")
	}
	if _, err := b.SendTextAs(context.Background(), b.cfg.NodeID, 0xCC, "dm"); err != nil {
		t.Fatal(err)
	}
	sent := mt.lastSent()
	if data, err := decryptWith(sent.packet, otherKey()); err != nil || string(data.Payload) != "dm" {
		t.Errorf("DM did not go out on the recorded channel's key: %v %v", data, err)
	}
}

// The handshake sends every channel slot with the configured ones at their
// indexes, and each NodeInfo carries the index of the channel that node was
// last heard on, so a phone can pick a DM channel.
func TestHandshakeSendsChannelTableAndNodeChannelIndex(t *testing.T) {
	secondKey := otherKey()
	n := newTestNode(t, newMockTransport(), func(c *Config) {
		c.Channels = &pb.ChannelSet{Settings: []*pb.ChannelSettings{
			{Name: "LongFast", Psk: crypto.DefaultKey},
			{Name: "SecondCh", Psk: secondKey},
		}}
	})
	n.NodeDB().Update(0xAA, func(info *pb.NodeInfo) { info.User = &pb.User{LongName: "Peer"} })
	n.NodeDB().SetChannel(0xAA, core.NewChannelWithKey("SecondCh", secondKey))
	n.NodeDB().Update(0xBB, func(info *pb.NodeInfo) { info.User = &pb.User{LongName: "Unheard"} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := stream.NewClientConn(n.Conn(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_WantConfigId{WantConfigId: 7}}); err != nil {
		t.Fatal(err)
	}

	var channels []*pb.Channel
	nodeChannel := map[uint32]uint32{}
handshake:
	for {
		var fr pb.FromRadio
		if err := conn.Read(&fr); err != nil {
			t.Fatalf("reading handshake: %v", err)
		}
		switch v := fr.PayloadVariant.(type) {
		case *pb.FromRadio_Channel:
			channels = append(channels, v.Channel)
		case *pb.FromRadio_NodeInfo:
			nodeChannel[v.NodeInfo.Num] = v.NodeInfo.Channel
		case *pb.FromRadio_ConfigCompleteId:
			break handshake
		}
	}

	if len(channels) != core.MaxChannels {
		t.Fatalf("got %d channel frames, want %d", len(channels), core.MaxChannels)
	}
	for i, ch := range channels {
		if int(ch.Index) != i {
			t.Errorf("frame %d has index %d", i, ch.Index)
		}
	}
	if channels[0].Role != pb.Channel_PRIMARY || channels[0].Settings.GetName() != "LongFast" {
		t.Errorf("slot 0 = %v, want PRIMARY LongFast", channels[0])
	}
	if channels[1].Role != pb.Channel_SECONDARY || channels[1].Settings.GetName() != "SecondCh" {
		t.Errorf("slot 1 = %v, want SECONDARY SecondCh", channels[1])
	}
	for _, ch := range channels[2:] {
		if ch.Role != pb.Channel_DISABLED {
			t.Errorf("slot %d role = %v, want DISABLED", ch.Index, ch.Role)
		}
	}
	if nodeChannel[0xAA] != 1 {
		t.Errorf("node heard on SecondCh reported channel index %d, want 1", nodeChannel[0xAA])
	}
	if nodeChannel[0xBB] != 0 {
		t.Errorf("unheard node reported channel index %d, want 0", nodeChannel[0xBB])
	}
}

// The visible symptom of name-only channel identity: a request arriving on the
// second of two same-name channels was answered on whichever channel the name
// resolved to first. Replies must go back on the exact channel the request used.
func TestBridgeRepliesOnTheRequestsExactChannel(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt, func(cfg *BridgeConfig) { cfg.Channels = sharedNameChannels() })
	sharedB := core.NewChannelWithKey("Shared", otherKey())

	telBytes, _ := proto.Marshal(&pb.Telemetry{})
	dataBytes, _ := proto.Marshal(&pb.Data{Portnum: pb.PortNum_TELEMETRY_APP, Payload: telBytes, WantResponse: true})
	encrypted, _ := crypto.XOR(dataBytes, otherKey(), 90, 0xAA)
	b.handleIncomingPacket(transport.NetworkPacket{Packet: &pb.MeshPacket{
		Id: 90, From: 0xAA, To: b.cfg.NodeID.Uint32(),
		Channel:        sharedB.GetHash(),
		PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: encrypted},
	}})

	if mt.sentCount() != 1 {
		t.Fatalf("sent %d packets, want the one telemetry reply", mt.sentCount())
	}
	reply := mt.lastSent().packet
	if reply.Channel != sharedB.GetHash() {
		t.Errorf("reply wire hash = %#x, want the request's %#x", reply.Channel, sharedB.GetHash())
	}
	data, err := decryptWith(reply, otherKey())
	if err != nil || data.Portnum != pb.PortNum_TELEMETRY_APP {
		t.Fatalf("reply does not decrypt with the request channel's key: data=%v err=%v", data, err)
	}
	if data.RequestId != 90 {
		t.Errorf("reply RequestId = %d, want 90", data.RequestId)
	}
	if d, err := decryptWith(reply, crypto.DefaultKey); err == nil && d.Portnum == pb.PortNum_TELEMETRY_APP {
		t.Error("reply also decrypts with the other same-name channel's key")
	}
}
