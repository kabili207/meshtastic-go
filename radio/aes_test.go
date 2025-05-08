package radio

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

const (
	testFromNode  = uint32(0x0929)
	testPacketNum = uint32(0x13b2d662)
)

var (
	testPublicKey, _  = hex.DecodeString("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457")
	testPrivateKey, _ = hex.DecodeString("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
	testShared, _     = hex.DecodeString("777b1545c9d6f9a2")
	testDecrypted, _  = hex.DecodeString("08011204746573744800")
	testRadioBytes, _ = hex.DecodeString("8c646d7a2909000062d6b2136b00000040df24abfcc30a17a3d9046726099e796a1c036a792b")
	testNonce, _      = hex.DecodeString("62d6b213036a792b2909000000")
)

// https://github.com/meshtastic/firmware/blob/62421a83fd602fc2c5fc17ed655de8ce1fe0d224/test/test_crypto/test_main.cpp#L113

func TestCreateNonce(t *testing.T) {

	extraNonce := binary.LittleEndian.Uint32(testRadioBytes[len(testRadioBytes)-4:])
	nonce := CreateNonce(testPacketNum, testFromNode, extraNonce)
	require.ElementsMatch(t, testNonce, nonce[:13])
}

func TestDecryptCurve25519(t *testing.T) {

	shared, _ := curve25519.X25519(testPrivateKey, testPublicKey)
	sharedKey := sha256.Sum256(shared)
	require.Equal(t, testShared, sharedKey[:8])

	decrypted, err := DecryptCurve25519(testRadioBytes[16:], shared, testPacketNum, testFromNode)
	require.NoError(t, err)
	require.Equal(t, testDecrypted, decrypted)

}

func TestEncryptCurve25519(t *testing.T) {

	shared, _ := curve25519.X25519(testPrivateKey, testPublicKey)
	sharedKey := sha256.Sum256(shared)
	require.Equal(t, testShared, sharedKey[:8])

	encrypted, err := EncryptCurve25519(testDecrypted, shared, testPacketNum, testFromNode)
	require.NoError(t, err)

	decrypted, err := DecryptCurve25519(encrypted, shared, testPacketNum, testFromNode)
	require.NoError(t, err)
	require.Equal(t, testDecrypted, decrypted)

}
