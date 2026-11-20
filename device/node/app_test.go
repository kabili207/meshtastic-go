package node

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

var secondaryKey = bytes.Repeat([]byte{0x33}, 32)

// appNode is a node with a primary and a secondary channel, and an app that has
// finished its handshake.
func appNode(t *testing.T) (*Node, *mockTransport, *stream.Conn) {
	t.Helper()
	mt := newMockTransport()
	n := newTestNode(t, mt, func(c *Config) {
		c.Channels = &pb.ChannelSet{Settings: []*pb.ChannelSettings{
			{Name: "LongFast", Psk: crypto.DefaultKey},
			{Name: "Side", Psk: secondaryKey},
		}}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app := stream.NewRadioConn(n.Conn(ctx))
	t.Cleanup(func() { app.Close() })
	if err := app.Write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_WantConfigId{WantConfigId: 1}}); err != nil {
		t.Fatal(err)
	}
	for {
		fr := &pb.FromRadio{}
		if err := app.Read(fr); err != nil {
			t.Fatal(err)
		}
		if fr.GetConfigCompleteId() == 1 {
			return n, mt, app
		}
	}
}

// appRead returns the next frame the app receives, failing after a second.
func appRead(t *testing.T, app *stream.Conn) *pb.FromRadio {
	t.Helper()
	got := make(chan *pb.FromRadio, 1)
	go func() {
		fr := &pb.FromRadio{}
		if app.Read(fr) == nil {
			got <- fr
		}
	}()
	select {
	case fr := <-got:
		return fr
	case <-time.After(time.Second):
		t.Fatal("app received nothing")
		return nil
	}
}

// Firmware hands the phone decoded packets, for broadcasts and for us only, with
// the channel as an index into the table it sent.
func TestAppReceivesDecodedPackets(t *testing.T) {
	n, mt, app := appNode(t)
	text := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("on the side")}

	other := pskPacket(t, n, 0xAA, 0xBB, 1, text)
	inject(n, mt, other)

	raw, _ := proto.Marshal(text)
	enc, _ := crypto.XOR(raw, secondaryKey, 2, 0xAA)
	inject(n, mt, pskPacketRaw(0xAA, core.BroadcastNodeID, 2, core.ChannelFromSettings(&pb.ChannelSettings{Name: "Side", Psk: secondaryKey}).GetHash(), enc))

	pkt := appRead(t, app).GetPacket()
	if pkt == nil || pkt.Id != 2 {
		t.Fatalf("app got %v, want only the broadcast", pkt)
	}
	if pkt.Channel != 1 {
		t.Errorf("channel %d, want index 1", pkt.Channel)
	}
	if string(pkt.GetDecoded().GetPayload()) != "on the side" {
		t.Error("the app was not given the decoded payload")
	}
}

func pskPacketRaw(from, to core.NodeID, id, hash uint32, enc []byte) transport.NetworkPacket {
	return transport.NetworkPacket{Channel: "Side", Packet: &pb.MeshPacket{
		Id: id, From: from.Uint32(), To: to.Uint32(), Channel: hash,
		PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: enc},
	}}
}

// The app may not pick the sender, its channel is an index, and its packet ID is
// kept so it can match acks.
func TestAppSend(t *testing.T) {
	_, mt, app := appNode(t)
	if err := app.Write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_Packet{Packet: &pb.MeshPacket{
		Id: 777, From: 0xDEAD, To: core.BroadcastNodeID.Uint32(), Channel: 1,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hi")}},
	}}}); err != nil {
		t.Fatal(err)
	}
	qs := appRead(t, app).GetQueueStatus()
	if qs == nil || qs.MeshPacketId != 777 || qs.Res != 0 {
		t.Fatalf("queue status %v, want success for packet 777", qs)
	}

	sent := mt.lastSent().packet
	if sent.Id != 777 || sent.From != 0x12345678 {
		t.Errorf("sent id %d from %v, want 777 from us", sent.Id, core.NodeID(sent.From))
	}
	if data, err := crypto.TryDecode(sent, secondaryKey); err != nil || string(data.Payload) != "hi" {
		t.Errorf("not sent on the secondary channel: %v", err)
	}
}

// A send firmware would refuse comes back to the app as a nak for that packet.
func TestAppSendFailureIsNakked(t *testing.T) {
	for name, tt := range map[string]struct {
		pkt  *pb.MeshPacket
		want pb.Routing_Error
	}{
		"unknown channel index": {&pb.MeshPacket{Id: 5, To: core.BroadcastNodeID.Uint32(), Channel: 5}, pb.Routing_NO_CHANNEL},
		"PKI without keys":      {&pb.MeshPacket{Id: 6, To: 0xAA, PkiEncrypted: true}, pb.Routing_PKI_FAILED},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, app := appNode(t)
			tt.pkt.PayloadVariant = &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP}}
			if err := app.Write(&pb.ToRadio{PayloadVariant: &pb.ToRadio_Packet{Packet: tt.pkt}}); err != nil {
				t.Fatal(err)
			}
			if qs := appRead(t, app).GetQueueStatus(); qs == nil || qs.Res == 0 {
				t.Errorf("queue status %v, want a failure", qs)
			}
			nak := appRead(t, app).GetPacket().GetDecoded()
			r := &pb.Routing{}
			if nak == nil || proto.Unmarshal(nak.Payload, r) != nil || r.GetErrorReason() != tt.want || nak.RequestId != tt.pkt.Id {
				t.Errorf("nak %v (%v), want %v for packet %d", nak, r.GetErrorReason(), tt.want, tt.pkt.Id)
			}
		})
	}
}
