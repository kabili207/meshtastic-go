package mqtt

import (
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

const selfNode = core.NodeID(0x12345678)

func testTransport() *Transport {
	return New(Config{NodeID: selfNode, Root: "msh/US"})
}

func envelope(pkt *pb.MeshPacket) *pb.ServiceEnvelope {
	return &pb.ServiceEnvelope{
		ChannelId: "LongFast",
		GatewayId: "!0000aabb",
		Packet:    pkt,
	}
}

func encryptedPacket() *pb.MeshPacket {
	return &pb.MeshPacket{
		From:           0x1234,
		To:             core.BroadcastNodeID.Uint32(),
		Id:             42,
		Channel:        0x08,
		HopLimit:       3,
		HopStart:       3,
		WantAck:        true,
		PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: []byte{1, 2, 3, 4}},
	}
}

func TestSanitizeInboundDrops(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*pb.ServiceEnvelope)
	}{
		{"missing channel id", func(se *pb.ServiceEnvelope) { se.ChannelId = "" }},
		{"missing gateway id", func(se *pb.ServiceEnvelope) { se.GatewayId = "" }},
		{"missing packet", func(se *pb.ServiceEnvelope) { se.Packet = nil }},
		{"published by ourselves", func(se *pb.ServiceEnvelope) { se.GatewayId = selfNode.String() }},
		{"from zero", func(se *pb.ServiceEnvelope) { se.Packet.From = 0 }},
		{"from broadcast", func(se *pb.ServiceEnvelope) { se.Packet.From = core.BroadcastNodeID.Uint32() }},
		{"from reserved", func(se *pb.ServiceEnvelope) { se.Packet.From = 2 }},
		{"hop_limit above max", func(se *pb.ServiceEnvelope) { se.Packet.HopLimit = core.MaxHops + 1 }},
		{"hop_start above max", func(se *pb.ServiceEnvelope) { se.Packet.HopStart = core.MaxHops + 1 }},
		{"no payload", func(se *pb.ServiceEnvelope) { se.Packet.PayloadVariant = nil }},
		{"plaintext admin", func(se *pb.ServiceEnvelope) {
			se.Packet.PayloadVariant = &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_ADMIN_APP}}
		}},
	}
	tr := testTransport()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			se := envelope(encryptedPacket())
			tt.mutate(se)
			if _, err := tr.sanitizeInbound(se); err == nil {
				t.Error("expected the packet to be dropped")
			}
		})
	}
}

func TestSanitizeInboundAccepts(t *testing.T) {
	tr := testTransport()

	t.Run("hop count at the limit", func(t *testing.T) {
		p := encryptedPacket()
		p.HopLimit, p.HopStart = core.MaxHops, core.MaxHops
		if _, err := tr.sanitizeInbound(envelope(p)); err != nil {
			t.Errorf("dropped: %v", err)
		}
	})

	t.Run("plaintext non-admin", func(t *testing.T) {
		p := encryptedPacket()
		p.PayloadVariant = &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hi")}}
		out, err := tr.sanitizeInbound(envelope(p))
		if err != nil {
			t.Fatalf("dropped: %v", err)
		}
		if out.GetDecoded().GetPortnum() != pb.PortNum_TEXT_MESSAGE_APP {
			t.Error("decoded payload was not carried over")
		}
	})
}

// Only the fields firmware copies may survive; everything a broker peer could
// set to look trusted must be absent from the rebuilt packet.
func TestSanitizeInboundRebuildsFromAllowlist(t *testing.T) {
	in := encryptedPacket()
	in.PkiEncrypted = true
	in.PublicKey = []byte{9, 9, 9}
	in.RxRssi = proto.Int32(-70)
	in.RxSnr = 8.5
	in.RxTime = proto.Uint32(1700000000)
	in.RelayNode = 0x99
	in.NextHop = 0x88
	in.Priority = pb.MeshPacket_ACK
	in.Delayed = pb.MeshPacket_DELAYED_DIRECT
	in.TransportMechanism = pb.MeshPacket_TRANSPORT_LORA

	out, err := testTransport().sanitizeInbound(envelope(in))
	if err != nil {
		t.Fatalf("valid packet was dropped: %v", err)
	}

	if out == in {
		t.Fatal("the wire packet was passed through instead of rebuilt")
	}
	if out.From != 0x1234 || out.To != core.BroadcastNodeID.Uint32() || out.Id != 42 || out.Channel != 0x08 {
		t.Error("routing fields were not carried over")
	}
	if out.HopLimit != 3 || out.HopStart != 3 || !out.WantAck {
		t.Error("hop and ack fields were not carried over")
	}
	if got := out.GetEncrypted(); len(got) != 4 || got[0] != 1 {
		t.Error("payload was not carried over")
	}

	if !out.ViaMqtt {
		t.Error("via_mqtt not set")
	}
	if out.TransportMechanism != pb.MeshPacket_TRANSPORT_MQTT {
		t.Errorf("transport_mechanism = %v, want MQTT", out.TransportMechanism)
	}

	if out.PkiEncrypted {
		t.Error("pki_encrypted survived")
	}
	if out.PublicKey != nil {
		t.Error("public_key survived")
	}
	if out.RxRssi != nil {
		t.Errorf("rx_rssi = %d, want absent", *out.RxRssi)
	}
	if out.RxSnr != 0 {
		t.Errorf("rx_snr = %v, want 0", out.RxSnr)
	}
	if out.RxTime != nil {
		t.Errorf("rx_time = %d, want absent", *out.RxTime)
	}
	if out.RelayNode != 0 || out.NextHop != 0 {
		t.Error("relay hints survived")
	}
	if out.Priority != pb.MeshPacket_UNSET || out.Delayed != pb.MeshPacket_NO_DELAY {
		t.Error("priority or delayed survived")
	}
}
