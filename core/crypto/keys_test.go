package crypto

import (
	"bytes"
	"testing"
)

func TestParseKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"default key AQ==", "AQ==", 16, false}, // Short PSK gets expanded
		{"full key", "1PG7OiApB1nwvP+rz05pAQ==", 16, false},
		{"url-safe base64", "1PG7OiApB1nwvP-rz05pAQ==", 16, false},
		{"invalid base64", "not-valid-base64!", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("ParseKey(%q) len = %d, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestExpandShortPSK(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
	}{
		{"empty returns default", nil, 16},
		{"empty slice returns default", []byte{}, 16},
		{"1 byte expands to 16", []byte{0x01}, 16},
		{"1 byte expands to 16 (255)", []byte{0xff}, 16},
		{"2 bytes pads to 16", []byte{0x01, 0x02}, 16},
		{"16 bytes unchanged", make([]byte, 16), 16},
		{"32 bytes unchanged", make([]byte, 32), 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandShortPSK(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("ExpandShortPSK() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}

	// Test that 1-byte expansion is deterministic
	exp1 := ExpandShortPSK([]byte{0x42})
	exp2 := ExpandShortPSK([]byte{0x42})
	if !bytes.Equal(exp1, exp2) {
		t.Error("ExpandShortPSK not deterministic")
	}

	// Test that different input bytes produce different keys
	exp3 := ExpandShortPSK([]byte{0x43})
	if bytes.Equal(exp1, exp3) {
		t.Error("ExpandShortPSK produced same key for different inputs")
	}
}

func TestTryCompactKey(t *testing.T) {
	// A 1-byte PSK expanded should compact back
	original := []byte{0x42}
	expanded := ExpandShortPSK(original)
	compacted := TryCompactKey(expanded)

	if !bytes.Equal(compacted, original) {
		t.Errorf("TryCompactKey() = %v, want %v", compacted, original)
	}

	// A non-simple key should not compact
	// Use DefaultKey which has a random pattern that doesn't match expansion
	notCompacted := TryCompactKey(DefaultKey)
	if !bytes.Equal(notCompacted, DefaultKey) {
		t.Error("TryCompactKey compacted a non-simple key")
	}
}

func TestChannelHash(t *testing.T) {
	// Test basic channel hash
	hash, err := ChannelHash("LongFast", DefaultKey)
	if err != nil {
		t.Errorf("ChannelHash error: %v", err)
	}
	if hash == 0 {
		t.Error("ChannelHash returned 0")
	}

	// Same inputs should produce same hash
	hash2, _ := ChannelHash("LongFast", DefaultKey)
	if hash != hash2 {
		t.Error("ChannelHash not deterministic")
	}

	// Different channel name should produce different hash
	hash3, _ := ChannelHash("ShortFast", DefaultKey)
	if hash == hash3 {
		t.Error("ChannelHash same for different channel names")
	}

	// Empty key should error
	_, err = ChannelHash("test", nil)
	if err == nil {
		t.Error("ChannelHash should error on empty key")
	}
}

func TestGenerateWeakKeys(t *testing.T) {
	keys := GenerateWeakKeys()
	// 256 * 3 = 768 keys (16, 24, 32 byte variants)
	if len(keys) != 768 {
		t.Errorf("GenerateWeakKeys() len = %d, want 768", len(keys))
	}

	// Check key lengths
	for i := 0; i < 256; i++ {
		if len(keys[i]) != 16 {
			t.Errorf("keys[%d] len = %d, want 16", i, len(keys[i]))
		}
		if len(keys[i+256]) != 24 {
			t.Errorf("keys[%d] len = %d, want 24", i+256, len(keys[i+256]))
		}
		if len(keys[i+512]) != 32 {
			t.Errorf("keys[%d] len = %d, want 32", i+512, len(keys[i+512]))
		}
	}
}
