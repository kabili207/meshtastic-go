package crypto

import (
	"encoding/base64"
	"errors"
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
// indexes into a family of keys derived from DefaultKey.
//
// The expansion follows the Meshtastic firmware (Channels.cpp getKey):
//   - Index 0: no encryption (returns nil-length key)
//   - Index 1-255: copy DefaultKey, then add (index-1) to the last byte
//
// This means index 1 (AQ==) produces the unmodified DefaultKey.
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

	// For 1-byte PSKs, derive from DefaultKey per firmware behavior
	if len(input) == 1 {
		index := input[0]
		if index == 0 {
			return make([]byte, 0) // No encryption
		}
		expanded := make([]byte, len(DefaultKey))
		copy(expanded, DefaultKey)
		expanded[len(expanded)-1] += index - 1
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
	if len(key) != len(DefaultKey) {
		return key
	}

	// Check if the first 15 bytes match DefaultKey
	for i := 0; i < len(DefaultKey)-1; i++ {
		if key[i] != DefaultKey[i] {
			return key
		}
	}

	// Last byte encodes the PSK index: index = lastByte - DefaultKey[last] + 1
	lastIdx := len(DefaultKey) - 1
	diff := key[lastIdx] - DefaultKey[lastIdx]
	index := diff + 1

	return []byte{index}
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
//
// An empty key is allowed and contributes nothing to the hash (matching the
// firmware, where unencrypted channels hash from the name alone).
//
// The caller is responsible for passing the resolved channel name. For the
// primary channel the firmware stores an empty name and substitutes the modem
// preset display name (e.g. "LongFast") before hashing; pass that resolved name
// here, not the empty string, or the hash will not match the firmware.
func ChannelHash(channelName string, channelKey []byte) uint32 {
	h := xorHash([]byte(channelName))
	h ^= xorHash(channelKey)

	return uint32(h)
}

// GenerateWeakKeys creates weak keys derived from DefaultKey for brute-force
// decryption of MQTT traffic using simple PSKs.
// For 16-byte keys, this produces the same keys as ExpandShortPSK for indices 0-255.
// Additionally generates 24-byte and 32-byte variants (zero-padded copies of DefaultKey
// with the last byte varied) for 192-bit and 256-bit AES.
func GenerateWeakKeys() [][]byte {
	allSlices := make([][]byte, 256*3)

	for i := 0; i < 256; i++ {
		// 16-byte keys: copy DefaultKey and set last byte
		// Index 0 gets DefaultKey with last byte = 0, matching no-offset expansion
		slice16 := make([]byte, 16)
		copy(slice16, DefaultKey)
		slice16[15] = DefaultKey[15] + byte(i) - 1
		allSlices[i] = slice16

		// 24-byte keys: DefaultKey zero-padded to 24 bytes, last byte varied
		slice24 := make([]byte, 24)
		copy(slice24, DefaultKey)
		slice24[23] = byte(i)
		allSlices[i+256] = slice24

		// 32-byte keys: DefaultKey zero-padded to 32 bytes, last byte varied
		slice32 := make([]byte, 32)
		copy(slice32, DefaultKey)
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
