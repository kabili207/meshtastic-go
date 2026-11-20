package crypto

import (
	"bytes"
	"testing"
)

// Firmware's getKey zero-pads short keys to the next AES size it supports.
func TestExpandShortPSKPadding(t *testing.T) {
	for _, n := range []int{2, 15, 17, 24, 31} {
		in := bytes.Repeat([]byte{0xAB}, n)
		got := ExpandShortPSK(in)
		want := 16
		if n > 16 {
			want = 32
		}
		if len(got) != want || !bytes.Equal(got[:n], in) || !bytes.Equal(got[n:], make([]byte, want-n)) {
			t.Errorf("%d bytes expanded to %x, want zero-padded to %d", n, got, want)
		}
	}
	for _, n := range []int{16, 32} {
		in := bytes.Repeat([]byte{0xAB}, n)
		if got := ExpandShortPSK(in); !bytes.Equal(got, in) {
			t.Errorf("%d-byte key changed", n)
		}
	}
}

// A channel with encryption off carries its payload as is.
func TestXORWithEmptyKeyIsNoop(t *testing.T) {
	text := []byte("plaintext payload")
	got, err := XOR(text, nil, 1, 2)
	if err != nil || !bytes.Equal(got, text) {
		t.Errorf("XOR with no key = %q, %v; want the input unchanged", got, err)
	}
}
