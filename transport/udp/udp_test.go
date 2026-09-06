package udp

import (
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

func encryptedPacket() *pb.MeshPacket {
	return &pb.MeshPacket{
		From:           0x1234,
		To:             0xFFFFFFFF,
		Id:             42,
		HopLimit:       3,
		HopStart:       3,
		PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: []byte{1, 2, 3, 4}},
	}
}

func TestNewDefaultsToCurrentMulticastGroup(t *testing.T) {
	tr := New(Config{})
	if got := tr.group.IP.String(); got != MulticastIP {
		t.Errorf("group = %s, want %s", got, MulticastIP)
	}
	if tr.group.Port != MulticastPort {
		t.Errorf("port = %d, want %d", tr.group.Port, MulticastPort)
	}
}

func TestNewHonorsConfiguredGroup(t *testing.T) {
	tr := New(Config{MulticastIP: LegacyMulticastIP})
	if got := tr.group.IP.String(); got != LegacyMulticastIP {
		t.Errorf("group = %s, want %s", got, LegacyMulticastIP)
	}
}

func TestSanitizeInboundDrops(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*pb.MeshPacket)
	}{
		{"already decoded", func(p *pb.MeshPacket) {
			p.PayloadVariant = &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP}}
		}},
		{"no payload", func(p *pb.MeshPacket) { p.PayloadVariant = nil }},
		{"from zero", func(p *pb.MeshPacket) { p.From = 0 }},
		{"hop_limit above max", func(p *pb.MeshPacket) { p.HopLimit = core.MaxHops + 1 }},
		{"hop_start above max", func(p *pb.MeshPacket) { p.HopStart = core.MaxHops + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := encryptedPacket()
			tt.mutate(p)
			if err := sanitizeInbound(p); err == nil {
				t.Error("expected the packet to be dropped")
			}
		})
	}
}

func TestSanitizeInboundAcceptsMaxHops(t *testing.T) {
	p := encryptedPacket()
	p.HopLimit = core.MaxHops
	p.HopStart = core.MaxHops
	if err := sanitizeInbound(p); err != nil {
		t.Errorf("hop count at the limit was dropped: %v", err)
	}
}

// A LAN peer can put anything in these fields. None of it may survive ingress.
func TestSanitizeInboundClearsUntrustedMetadata(t *testing.T) {
	p := encryptedPacket()
	p.PkiEncrypted = true
	p.PublicKey = []byte{9, 9, 9}
	p.RxRssi = proto.Int32(-70)
	p.RxSnr = 8.5
	p.TransportMechanism = pb.MeshPacket_TRANSPORT_LORA

	if err := sanitizeInbound(p); err != nil {
		t.Fatalf("valid packet was dropped: %v", err)
	}
	if p.PkiEncrypted {
		t.Error("pki_encrypted survived ingress")
	}
	if p.PublicKey != nil {
		t.Error("public_key survived ingress")
	}
	if p.RxRssi != nil {
		t.Errorf("rx_rssi = %d, want absent", *p.RxRssi)
	}
	if p.RxSnr != 0 {
		t.Errorf("rx_snr = %v, want 0", p.RxSnr)
	}
	if p.TransportMechanism != pb.MeshPacket_TRANSPORT_MULTICAST_UDP {
		t.Errorf("transport_mechanism = %v, want multicast UDP", p.TransportMechanism)
	}
}

// Sanitizing must not touch the fields that carry the packet itself.
func TestSanitizeInboundPreservesPayload(t *testing.T) {
	p := encryptedPacket()
	if err := sanitizeInbound(p); err != nil {
		t.Fatal(err)
	}
	if p.From != 0x1234 || p.To != 0xFFFFFFFF || p.Id != 42 || p.HopLimit != 3 {
		t.Error("routing fields were altered")
	}
	if got := p.GetEncrypted(); len(got) != 4 || got[0] != 1 {
		t.Error("encrypted payload was altered")
	}
}
