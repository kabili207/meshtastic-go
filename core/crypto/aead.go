package crypto

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
)

// AEADOverhead is the AES-CCM tag a channel with use_aead appends to every
// payload, matching firmware's MESHTASTIC_AEAD_OVERHEAD.
const AEADOverhead = 12

// EncryptAEAD encrypts a channel payload with AES-CCM, as firmware's
// encryptPacketCCM does for channels with use_aead set. The nonce is the one
// AES-CTR uses, cut to 13 bytes, and the sender and destination are bound in as
// associated data, so a packet cannot be re-addressed without failing its tag.
func EncryptAEAD(text, key []byte, packetID, fromNode, toNode uint32) ([]byte, error) {
	c, err := aeadCipher(key)
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, CreateNonce(packetID, fromNode, 0)[:13], text, aeadAAD(fromNode, toNode)), nil
}

// DecryptAEAD reverses EncryptAEAD, failing when the tag does not verify.
func DecryptAEAD(text, key []byte, packetID, fromNode, toNode uint32) ([]byte, error) {
	if len(text) <= AEADOverhead {
		return nil, ErrDecrypt
	}
	c, err := aeadCipher(key)
	if err != nil {
		return nil, err
	}
	plain, err := c.Open(nil, CreateNonce(packetID, fromNode, 0)[:13], text, aeadAAD(fromNode, toNode))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func aeadCipher(key []byte) (ccm.CCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ccm.NewCCM(block, AEADOverhead, 13)
}

func aeadAAD(fromNode, toNode uint32) []byte {
	aad := make([]byte, 8)
	binary.LittleEndian.PutUint32(aad, fromNode)
	binary.LittleEndian.PutUint32(aad[4:], toNode)
	return aad
}
