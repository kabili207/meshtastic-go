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
		{"index 0 no encryption", []byte{0x00}, 0},
		{"index 1 expands to 16", []byte{0x01}, 16},
		{"index 255 expands to 16", []byte{0xff}, 16},
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

	// Index 1 (AQ==) must produce unmodified DefaultKey
	idx1 := ExpandShortPSK([]byte{0x01})
	if !bytes.Equal(idx1, DefaultKey) {
		t.Errorf("ExpandShortPSK(0x01) = %x, want DefaultKey %x", idx1, DefaultKey)
	}

	// Index 2 should differ only in the last byte (+1)
	idx2 := ExpandShortPSK([]byte{0x02})
	if !bytes.Equal(idx2[:15], DefaultKey[:15]) {
		t.Error("ExpandShortPSK(0x02) first 15 bytes should match DefaultKey")
	}
	if idx2[15] != DefaultKey[15]+1 {
		t.Errorf("ExpandShortPSK(0x02) last byte = 0x%02x, want 0x%02x", idx2[15], DefaultKey[15]+1)
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

	// DefaultKey is index 1 (AQ==), so it should compact to [0x01]
	compactedDefault := TryCompactKey(DefaultKey)
	if !bytes.Equal(compactedDefault, []byte{0x01}) {
		t.Errorf("TryCompactKey(DefaultKey) = %v, want [0x01]", compactedDefault)
	}

	// A completely different key should not compact
	randomKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	notCompacted := TryCompactKey(randomKey)
	if !bytes.Equal(notCompacted, randomKey) {
		t.Error("TryCompactKey compacted a non-DefaultKey-derived key")
	}
}

func TestChannelHash(t *testing.T) {
	// Test basic channel hash
	hash := ChannelHash("LongFast", DefaultKey)
	if hash == 0 {
		t.Error("ChannelHash returned 0")
	}

	// Same inputs should produce same hash
	hash2 := ChannelHash("LongFast", DefaultKey)
	if hash != hash2 {
		t.Error("ChannelHash not deterministic")
	}

	// Different channel name should produce different hash
	hash3 := ChannelHash("ShortFast", DefaultKey)
	if hash == hash3 {
		t.Error("ChannelHash same for different channel names")
	}

	// An empty key is allowed; the hash comes from the name alone and must
	// match the firmware, which hashes unencrypted channels the same way.
	if got, want := ChannelHash("test", nil), uint32(xorHash([]byte("test"))); got != want {
		t.Errorf("ChannelHash with empty key = %d, want %d", got, want)
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

	// 16-byte keys should be derived from DefaultKey (first 15 bytes match)
	for i := 0; i < 256; i++ {
		if !bytes.Equal(keys[i][:15], DefaultKey[:15]) {
			t.Errorf("keys[%d] first 15 bytes don't match DefaultKey", i)
			break
		}
	}

	// Key at index 1 should be unmodified DefaultKey (matches PSK index 1 = AQ==)
	// Index in the array maps to: lastByte = DefaultKey[15] + i - 1
	// So array index 1 → lastByte = DefaultKey[15] + 0 = DefaultKey[15] → DefaultKey itself
	if !bytes.Equal(keys[1], DefaultKey) {
		t.Errorf("keys[1] = %x, want DefaultKey %x", keys[1], DefaultKey)
	}
}
