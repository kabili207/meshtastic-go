package node

import (
	"testing"
)

func TestPacketIDGenerator_LowerBitsIncrement(t *testing.T) {
	g := &packetIDGenerator{}

	ids := make([]uint32, 100)
	for i := range ids {
		ids[i] = g.next()
	}

	// The lower 10 bits should be incrementing (modulo 1024)
	for i := 1; i < len(ids); i++ {
		prevLow := ids[i-1] & 0x3FF
		currLow := ids[i] & 0x3FF
		expected := (prevLow + 1) & 0x3FF
		if currLow != expected {
			t.Errorf("id[%d] lower 10 bits = %d, expected %d (prev was %d)",
				i, currLow, expected, prevLow)
		}
	}
}

func TestPacketIDGenerator_UpperBitsVary(t *testing.T) {
	g := &packetIDGenerator{}

	ids := make([]uint32, 50)
	for i := range ids {
		ids[i] = g.next()
	}

	// The upper 22 bits should not all be the same
	upper := make(map[uint32]bool)
	for _, id := range ids {
		upper[id>>10] = true
	}
	if len(upper) < 2 {
		t.Error("expected upper 22 bits to vary across calls")
	}
}

func TestPacketIDGenerator_NeverZero(t *testing.T) {
	g := &packetIDGenerator{}
	for range 1000 {
		id := g.next()
		if id == 0 {
			t.Fatal("packet ID should never be zero")
		}
	}
}
