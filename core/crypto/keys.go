package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	pb "github.com/kabili207/meshtastic-go/core/generated"
	"google.golang.org/protobuf/proto"
)

// DefaultKey is the default encryption key, commonly referenced as AQ==
// as base64: 1PG7OiApB1nwvP+rz05pAQ==
var DefaultKey = []byte{0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}

// ErrDecrypt is returned when packet decryption fails
var ErrDecrypt = errors.New("unable to decrypt payload")

// ParseKey converts a base64 encoded channel encryption key to a byte slice.
// Supports both standard and URL-safe base64 encoding.
func ParseKey(key string) ([]byte, error) {
	if strings.ContainsAny(key, "-_") {
		return base64.URLEncoding.DecodeString(key)
	}
	return base64.StdEncoding.DecodeString(key)
}

// xorHash computes a simple XOR hash of the provided byte slice.
func xorHash(p []byte) uint8 {
	var code uint8
	for _, b := range p {
		code ^= b
	}
	return code
}

// ChannelHash returns the hash for a given channel by XORing the channel name and PSK.
func ChannelHash(channelName string, channelKey []byte) (uint32, error) {
	if len(channelKey) == 0 {
		return 0, fmt.Errorf("channel key cannot be empty")
	}

	h := xorHash([]byte(channelName))
	h ^= xorHash(channelKey)

	return uint32(h), nil
}

// GenerateWeakKeys creates a bunch of weak keys for use when interfacing on MQTT.
// This creates 128, 192, and 256 bit AES keys with only a single byte specified.
func GenerateWeakKeys() [][]byte {
	// There are 256 possible values for a single byte
	// We create 768 slices: 256 with 16 bytes, 256 with 24 bytes, and 256 with 32 bytes
	allSlices := make([][]byte, 256*3)

	for i := 0; i < 256; i++ {
		// Create a slice of 16 bytes for the first 256 slices
		slice16 := make([]byte, 16)
		slice16[15] = byte(i)
		allSlices[i] = slice16

		// Create a slice of 24 bytes (192 bits) for the next 256 slices
		slice24 := make([]byte, 24)
		slice24[23] = byte(i)
		allSlices[i+256] = slice24

		// Create a slice of 32 bytes for the last 256 slices
		slice32 := make([]byte, 32)
		slice32[31] = byte(i)
		allSlices[i+512] = slice32
	}

	return allSlices
}

// TryDecodePKI attempts to decrypt the packet with the specified public key and private key.
// The public key should be the sending node's key and the private key should be
// the receiving node's private key.
func TryDecodePKI(packet *pb.MeshPacket, publicKey, privateKey []byte) (*pb.Data, error) {
	if x, ok := packet.GetPayloadVariant().(*pb.MeshPacket_Encrypted); ok &&
		packet.Channel == 0 && packet.To > 0 && len(x.Encrypted) > MeshtasticPKCOverhead {
		packet.PkiEncrypted = true
		packet.PublicKey = publicKey
	}
	return TryDecode(packet, privateKey)
}

// TryDecode attempts to decrypt a packet with the specified key, or return the already decrypted data if present.
func TryDecode(packet *pb.MeshPacket, key []byte) (*pb.Data, error) {
	switch packet.GetPayloadVariant().(type) {
	case *pb.MeshPacket_Decoded:
		return packet.GetDecoded(), nil
	case *pb.MeshPacket_Encrypted:
		var err error
		var decrypted []byte
		if !packet.PkiEncrypted {
			decrypted, err = XOR(packet.GetEncrypted(), key, packet.Id, packet.From)
		} else {
			decrypted, err = DecryptCurve25519(packet.GetEncrypted(), key, packet.PublicKey, packet.Id, packet.From)
		}

		if err != nil {
			return nil, ErrDecrypt
		}

		var meshPacket pb.Data
		err = proto.Unmarshal(decrypted, &meshPacket)
		if err != nil {
			return nil, ErrDecrypt
		}
		return &meshPacket, nil
	default:
		return nil, errors.New("unknown payload variant")
	}
}
