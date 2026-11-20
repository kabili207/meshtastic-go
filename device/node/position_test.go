package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/lora"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

func sentPosition(t *testing.T, mt *mockTransport, key []byte) (*pb.MeshPacket, *pb.Position) {
	t.Helper()
	sent := mt.lastSent().packet
	data, err := crypto.TryDecode(sent, key)
	if err != nil {
		t.Fatalf("decrypting sent position: %v", err)
	}
	pos := &pb.Position{}
	if err := proto.Unmarshal(data.Payload, pos); err != nil {
		t.Fatal(err)
	}
	return sent, pos
}

// A channel whose key anyone can derive is clamped to 15 bits however finely it is
// configured, as firmware's getPositionPrecisionForChannel does.
func TestBroadcastPositionClampedOnPublicChannel(t *testing.T) {
	mt := newMockTransport()
	n := positionNode(t, mt, 32)
	if err := n.broadcastPosition(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, pos := sentPosition(t, mt, crypto.DefaultKey)
	if pos.PrecisionBits != core.MaxPositionPrecisionPublicKey {
		t.Errorf("precision_bits = %d, want %d", pos.PrecisionBits, core.MaxPositionPrecisionPublicKey)
	}
	if want := lora.TruncateCoordinate(400_000_000, core.MaxPositionPrecisionPublicKey); pos.GetLatitudeI() != want {
		t.Errorf("latitude %d, want truncated %d", pos.GetLatitudeI(), want)
	}
}

// Firmware fails closed: with no channel allowing any precision, no position is
// sent, as a broadcast or a reply.
func TestPositionNotSentWhenSharingIsOff(t *testing.T) {
	mt := newMockTransport()
	n := positionNode(t, mt, 0)
	if err := n.broadcastPosition(context.Background()); err != nil {
		t.Fatal(err)
	}
	inject(n, mt, decodedPacket(0xAA, n.cfg.NodeID, 1, positionRequest()))
	if mt.sentCount() != 0 {
		t.Errorf("sent %d packets with position sharing off", mt.sentCount())
	}
}

func TestPositionNotSentWithoutCoordinates(t *testing.T) {
	mt := newMockTransport()
	n := positionNode(t, mt, 32)
	n.cfg.PositionLatitudeI, n.cfg.PositionLongitudeI = 0, 0
	if err := n.broadcastPosition(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mt.sentCount() != 0 {
		t.Error("sent a position with no coordinates")
	}
}

// The lowest-indexed channel that shares at all carries the position, at its own
// precision, rather than the primary.
func TestPositionUsesLowestSharingChannel(t *testing.T) {
	private := make([]byte, 32)
	for i := range private {
		private[i] = byte(i + 1)
	}
	mt := newMockTransport()
	n := newTestNode(t, mt, func(c *Config) {
		c.PositionLatitudeI = 400_000_000
		c.PositionLongitudeI = -800_000_000
		c.Channels = &pb.ChannelSet{Settings: []*pb.ChannelSettings{
			{Name: "LongFast", Psk: crypto.DefaultKey},
			{Name: "Private", Psk: private, ModuleSettings: &pb.ModuleSettings{PositionPrecision: 32}},
		}}
	})
	if err := n.broadcastPosition(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent, pos := sentPosition(t, mt, private)
	if mt.lastSent().channel != "Private" {
		t.Errorf("sent on %q, want Private", mt.lastSent().channel)
	}
	if pos.PrecisionBits != 32 || pos.GetLatitudeI() != 400_000_000 {
		t.Errorf("precision %d, latitude %d; want full precision on a private channel", pos.PrecisionBits, pos.GetLatitudeI())
	}
	if sent.Channel != core.ChannelFromSettings(n.cfg.Channels.Settings[1]).GetHash() {
		t.Error("channel hash does not match the private channel")
	}
}

// A request we could not answer must not use up the reply window, as firmware
// only counts a reply it actually sends.
func TestUnansweredPositionRequestKeepsReplyWindow(t *testing.T) {
	mt := newMockTransport()
	n := positionNode(t, mt, 0)
	inject(n, mt, decodedPacket(0xAA, n.cfg.NodeID, 1, positionRequest()))

	n.cfg.Channels.Settings[0].ModuleSettings.PositionPrecision = 32
	inject(n, mt, decodedPacket(0xBB, n.cfg.NodeID, 2, positionRequest()))
	if mt.sentCount() != 1 {
		t.Errorf("sent %d replies, want 1 once sharing was enabled", mt.sentCount())
	}
}
