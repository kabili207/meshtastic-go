package core

import (
	"strings"
	"testing"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

func presetPtr(p pb.Config_LoRaConfig_ModemPreset) *pb.Config_LoRaConfig_ModemPreset { return &p }

func TestMeshBeaconHasOffer(t *testing.T) {
	tests := []struct {
		name string
		b    *pb.MeshBeacon
		want bool
	}{
		{"nil", nil, false},
		{"empty", &pb.MeshBeacon{}, false},
		{"text only", &pb.MeshBeacon{Message: "hello"}, false},
		{"channel", &pb.MeshBeacon{OfferChannel: &pb.ChannelSettings{Name: "Camp"}}, true},
		{"region", &pb.MeshBeacon{OfferRegion: pb.Config_LoRaConfig_US}, true},
		{"preset", &pb.MeshBeacon{OfferPreset: presetPtr(pb.Config_LoRaConfig_LONG_FAST)}, true},
	}
	for _, tt := range tests {
		if got := MeshBeaconHasOffer(tt.b); got != tt.want {
			t.Errorf("%s: MeshBeaconHasOffer = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestValidateMeshBeacon(t *testing.T) {
	tests := []struct {
		name    string
		b       *pb.MeshBeacon
		wantErr bool
	}{
		{"nil", nil, true},
		{"neither text nor offer", &pb.MeshBeacon{}, true},
		{"text only", &pb.MeshBeacon{Message: "hello"}, false},
		{"offer only", &pb.MeshBeacon{OfferRegion: pb.Config_LoRaConfig_EU_868}, false},
		{"message at the limit", &pb.MeshBeacon{Message: strings.Repeat("x", MaxMeshBeaconMessage)}, false},
		{"message over the limit", &pb.MeshBeacon{Message: strings.Repeat("x", MaxMeshBeaconMessage+1)}, true},
		{"channel name at the limit", &pb.MeshBeacon{OfferChannel: &pb.ChannelSettings{Name: strings.Repeat("c", MaxChannelName)}}, false},
		{"channel name over the limit", &pb.MeshBeacon{OfferChannel: &pb.ChannelSettings{Name: strings.Repeat("c", MaxChannelName+1)}}, true},
		{"psk at the limit", &pb.MeshBeacon{OfferChannel: &pb.ChannelSettings{Psk: make([]byte, MaxChannelPSK)}}, false},
		{"psk over the limit", &pb.MeshBeacon{OfferChannel: &pb.ChannelSettings{Psk: make([]byte, MaxChannelPSK+1)}}, true},
	}
	for _, tt := range tests {
		err := ValidateMeshBeacon(tt.b)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: ValidateMeshBeacon error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}
