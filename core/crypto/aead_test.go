package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Produced by compiling firmware v2.8.2's aes-ccm.cpp against OpenSSL's AES
// block, with the nonce and AAD built as encryptPacketCCM builds them.
func TestEncryptAEADMatchesFirmware(t *testing.T) {
	const (
		from     = uint32(0xA1B2C3D4)
		to       = uint32(0xFFFFFFFF)
		packetID = uint32(0x0F1E2D3C)
	)
	plain := []byte("hello aead mesh")
	want, _ := hex.DecodeString("9b2cc796dd925fd144f080c924f1724f8a69a39fbf9123e20cf942")

	got, err := EncryptAEAD(plain, DefaultKey, packetID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EncryptAEAD =\n%x, want\n%x", got, want)
	}
	back, err := DecryptAEAD(want, DefaultKey, packetID, from, to)
	if err != nil || !bytes.Equal(back, plain) {
		t.Errorf("DecryptAEAD = %q, %v", back, err)
	}
}

// The tag covers the sender and destination, so re-addressing a packet breaks it.
func TestDecryptAEADRejectsTampering(t *testing.T) {
	sealed, err := EncryptAEAD([]byte("payload"), DefaultKey, 1, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(sealed)
	flipped[0] ^= 1
	cases := map[string]func() ([]byte, error){
		"ciphertext changed": func() ([]byte, error) { return DecryptAEAD(flipped, DefaultKey, 1, 2, 3) },
		"re-addressed":       func() ([]byte, error) { return DecryptAEAD(sealed, DefaultKey, 1, 2, 4) },
		"other sender":       func() ([]byte, error) { return DecryptAEAD(sealed, DefaultKey, 1, 5, 3) },
		"too short":          func() ([]byte, error) { return DecryptAEAD(sealed[:AEADOverhead], DefaultKey, 1, 2, 3) },
	}
	for name, decrypt := range cases {
		if _, err := decrypt(); err == nil {
			t.Errorf("%s: decrypted without error", name)
		}
	}
}
