package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// DefaultKey is the default encryption key, commonly referenced as AQ==
// as base64: 1PG7OiApB1nwvP+rz05pAQ==
var DefaultKey = []byte{0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}

// ErrDecrypt is returned when packet decryption fails
var ErrDecrypt = errors.New("unable to decrypt payload")

// ParseKey converts a base64 encoded channel encryption key to a byte slice.
// Supports both standard and URL-safe base64 encoding.
// Short PSKs (1 byte when decoded) are automatically expanded to full 16-byte keys.
func ParseKey(key string) ([]byte, error) {
	var decoded []byte
	var err error
	if strings.ContainsAny(key, "-_") {
		decoded, err = base64.URLEncoding.DecodeString(key)
	} else {
		decoded, err = base64.StdEncoding.DecodeString(key)
	}
	if err != nil {
		return nil, err
	}

	// Expand short PSKs to full keys
	return ExpandShortPSK(decoded), nil
}

// ExpandShortPSK expands a 1-byte "simple" PSK to a full 16-byte key.
// Meshtastic supports short PSKs for convenience - a single byte (0-255) that
// gets expanded to a full AES key by repeating a specific pattern.
//
// If the input is already 16+ bytes, it's returned unchanged.
// If the input is empty, DefaultKey is returned.
func ExpandShortPSK(input []byte) []byte {
	if len(input) == 0 {
		return DefaultKey
	}
	if len(input) >= 16 {
		return input
	}

	// For 1-byte PSKs, expand using the simple PSK pattern
	// The pattern fills bytes 0-14 with a rotating value based on the input byte
	if len(input) == 1 {
		expanded := make([]byte, 16)
		pskByte := input[0]

		// Pattern from Meshtastic firmware: simple PSK expansion
		// Byte 0 = pskByte, then incrementing pattern
		for i := 0; i < 16; i++ {
			expanded[i] = pskByte + byte(i)
		}
		return expanded
	}

	// For 2-15 byte inputs, pad with zeros to 16 bytes
	expanded := make([]byte, 16)
	copy(expanded, input)
	return expanded
}

// TryCompactKey attempts to compact a full key back to its short form if possible.
// Returns the original key if it can't be compacted.
func TryCompactKey(key []byte) []byte {
	if len(key) != 16 {
		return key
	}

	// Check if this matches the expanded pattern for a 1-byte PSK
	firstByte := key[0]
	isSimplePSK := true
	for i := 1; i < 16; i++ {
		if key[i] != firstByte+byte(i) {
			isSimplePSK = false
			break
		}
	}

	if isSimplePSK {
		return []byte{firstByte}
	}

	return key
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
