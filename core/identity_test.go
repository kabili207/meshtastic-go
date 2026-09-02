package core

import (
	"bytes"
	"testing"
)

// crossCheckedKey and crossCheckedID were produced by compiling firmware's CRC32
// dependency (ErriezCRC32, as used by NodeDB's crc32Buffer) against this exact key and
// comparing its output to crc32.ChecksumIEEE. Both emit a10e8695, which is what pins
// our derivation to the firmware's.
var (
	crossCheckedKey = func() []byte {
		k := make([]byte, PublicKeySize)
		for i := range k {
			k[i] = byte(i*7 + 3)
		}
		return k
	}()
	crossCheckedID = NodeID(0xa10e8695)
)

func TestNodeIDFromPublicKey(t *testing.T) {
	got, err := NodeIDFromPublicKey(crossCheckedKey)
	if err != nil {
		t.Fatalf("NodeIDFromPublicKey: unexpected error: %v", err)
	}
	if got != crossCheckedID {
		t.Errorf("NodeIDFromPublicKey = %s (%#08x), want %s (%#08x)",
			got, uint32(got), crossCheckedID, uint32(crossCheckedID))
	}
}

func TestNodeIDFromPublicKeyIsDeterministic(t *testing.T) {
	first, err := NodeIDFromPublicKey(crossCheckedKey)
	if err != nil {
		t.Fatalf("NodeIDFromPublicKey: unexpected error: %v", err)
	}
	second, err := NodeIDFromPublicKey(bytes.Clone(crossCheckedKey))
	if err != nil {
		t.Fatalf("NodeIDFromPublicKey: unexpected error: %v", err)
	}
	if first != second {
		t.Errorf("same key produced %s then %s", first, second)
	}
}

func TestNodeIDFromPublicKeyRejectsWrongLength(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64} {
		if _, err := NodeIDFromPublicKey(make([]byte, size)); err == nil {
			t.Errorf("NodeIDFromPublicKey with %d-byte key: expected an error", size)
		}
	}
	if _, err := NodeIDFromPublicKey(nil); err == nil {
		t.Error("NodeIDFromPublicKey(nil): expected an error")
	}
}

func TestMatchesPublicKey(t *testing.T) {
	otherKey := bytes.Clone(crossCheckedKey)
	otherKey[0] ^= 0x01

	tests := []struct {
		name string
		id   NodeID
		key  []byte
		want bool
	}{
		{"derived id matches its key", crossCheckedID, crossCheckedKey, true},
		{"different id rejects the key", crossCheckedID ^ 1, crossCheckedKey, false},
		{"one flipped key bit rejects", crossCheckedID, otherKey, false},
		{"short key rejects", crossCheckedID, crossCheckedKey[:31], false},
		{"nil key rejects", crossCheckedID, nil, false},
		{"zero id rejects", 0, crossCheckedKey, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.MatchesPublicKey(tt.key); got != tt.want {
				t.Errorf("NodeID(%#08x).MatchesPublicKey(%d bytes) = %v, want %v",
					uint32(tt.id), len(tt.key), got, tt.want)
			}
		})
	}
}
