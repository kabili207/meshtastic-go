package core

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Expected hashes are xorHash(name) ^ xorHash(key), computed independently.
func TestChannelsFromSet(t *testing.T) {
	custom := bytes.Repeat([]byte{0x42}, 32)
	tests := []struct {
		name     string
		set      *pb.ChannelSet
		index    int
		wantName string
		wantKey  []byte
		wantHash uint32
	}{
		{
			name:     "empty primary name takes the default preset's",
			set:      &pb.ChannelSet{Settings: []*pb.ChannelSettings{{Psk: []byte{1}}}},
			wantName: "LongFast", wantKey: crypto.DefaultKey, wantHash: 8,
		},
		{
			name:     "legacy Default name takes the preset's",
			set:      &pb.ChannelSet{Settings: []*pb.ChannelSettings{{Name: "Default", Psk: []byte{1}}}},
			wantName: "LongFast", wantKey: crypto.DefaultKey, wantHash: 8,
		},
		{
			name: "preset from the set's LoRa config",
			set: &pb.ChannelSet{
				Settings:   []*pb.ChannelSettings{{Psk: []byte{1}}},
				LoraConfig: &pb.Config_LoRaConfig{UsePreset: true, ModemPreset: pb.Config_LoRaConfig_MEDIUM_FAST},
			},
			wantName: "MediumFast", wantKey: crypto.DefaultKey, wantHash: 31,
		},
		{
			name: "no preset means Custom",
			set: &pb.ChannelSet{
				Settings:   []*pb.ChannelSettings{{Psk: []byte{1}}},
				LoraConfig: &pb.Config_LoRaConfig{UsePreset: false},
			},
			wantName: "Custom", wantKey: crypto.DefaultKey,
		},
		{
			name:     "empty primary PSK means no encryption",
			set:      &pb.ChannelSet{Settings: []*pb.ChannelSettings{{Name: "LongFast"}}},
			wantName: "LongFast", wantKey: []byte{}, wantHash: 10,
		},
		{
			name: "secondary with no PSK borrows the primary's",
			set: &pb.ChannelSet{Settings: []*pb.ChannelSettings{
				{Name: "Main", Psk: custom},
				{Name: "Side"},
			}},
			index: 1, wantName: "Side", wantKey: custom,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := ChannelsFromSet(tt.set)[tt.index]
			if ch.Name != tt.wantName {
				t.Errorf("name %q, want %q", ch.Name, tt.wantName)
			}
			if !bytes.Equal(ch.Key, tt.wantKey) {
				t.Errorf("key %x, want %x", ch.Key, tt.wantKey)
			}
			if tt.wantHash != 0 && ch.GetHash() != tt.wantHash {
				t.Errorf("hash %d, want %d", ch.GetHash(), tt.wantHash)
			}
		})
	}
}
