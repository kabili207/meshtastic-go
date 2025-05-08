package radio

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	mathRand "math/rand/v2"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
	"golang.org/x/crypto/curve25519"
)

const (
	MeshtasticPKCOverhead = 12
)

// CreateNonce creates a 128-bit nonce.
// It takes a uint32 packetId, converts it to a uint64, and a uint32 fromNode.
// The nonce is concatenated as [64-bit packetId][32-bit fromNode][32-bit block counter].
func CreateNonce(packetId uint32, fromNode uint32, extraNonce uint32) []byte {
	nonce := make([]byte, 16)

	binary.LittleEndian.PutUint64(nonce[0:], uint64(packetId))
	binary.LittleEndian.PutUint32(nonce[8:], fromNode)

	if extraNonce != 0 {
		binary.LittleEndian.PutUint32(nonce[4:], extraNonce)
	}

	return nonce
}

// XOR encrypts or decrypts text with the specified key. It requires the packetID and sending node ID for the AES IV
func XOR(text []byte, key []byte, packetID, fromNode uint32) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("key length must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. It's common to include it at
	// the beginning of the text. In CTR mode, the IV size is equal to the block size.
	//if len(text) < aes.BlockSize {
	//	return nil, fmt.Errorf("text too short")
	//}
	iv := CreateNonce(packetID, fromNode, 0)
	//text = text[aes.BlockSize:]

	// CTR mode is the same for both encryption and decryption, so we use
	// the NewCTR function rather than NewCBCDecrypter.
	stream := cipher.NewCTR(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	plaintext := make([]byte, len(text))
	stream.XORKeyStream(plaintext, text)

	return plaintext, nil
}

func GenerateKeyPair() (publicKey, privateKey []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

// Performs AES-CCM encryption with the specified ECDH shared key. It requires the packetID and sending node ID for the AES IV
func EncryptCurve25519(text, privateKey, publicKey []byte, packetID, fromNode uint32) ([]byte, error) {
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes")
	}

	key, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, errors.New("could not create shared key")
	}

	sharedKey := sha256.Sum256(key[:])
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, err
	}
	// This doesn't need to be cryptographically secure, so we'll just use a
	// psuedo-random number to prevent us from exhausting our entropy source
	// Must be non-negative to prevent issues
	extraNonce := uint32(mathRand.Int32())
	iv := CreateNonce(packetID, fromNode, extraNonce)

	ccmBlock, err := ccm.NewCCM(block, 8, 13)
	if err != nil {
		return nil, err
	}
	ciphertext := ccmBlock.Seal(nil, iv[:13], text, nil)

	// Append extraNonce to the ciphertext
	extraNonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(extraNonceBytes, extraNonce)
	ciphertext = append(ciphertext, extraNonceBytes...)

	return ciphertext, nil
}

// Performs AES-CCM decryption with the specified ECDH shared key. It requires the packetID and sending node ID for the AES IV
func DecryptCurve25519(text, privateKey, publicKey []byte, packetID, fromNode uint32) ([]byte, error) {
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes")
	}

	key, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, errors.New("could not create shared key")
	}

	sharedKey := sha256.Sum256(key[:])
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, err
	}

	cipherText := text[:len(text)-4]
	extraNonce := binary.LittleEndian.Uint32(text[len(text)-4:])

	iv := CreateNonce(packetID, fromNode, extraNonce)

	s, err := ccm.NewCCM(block, 8, 13)
	if err != nil {
		return nil, err
	}
	return s.Open(nil, iv[:13], cipherText, nil)
}
