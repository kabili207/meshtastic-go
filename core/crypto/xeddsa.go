package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/curve25519"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// XEdDSA lets a node sign with the same X25519 identity key it already uses for PKI,
// instead of carrying a second keypair. Signing derives an Ed25519 scalar from the
// X25519 private key; verifying maps the sender's X25519 public key onto the Ed25519
// curve and then checks an ordinary Ed25519 signature.
//
// See https://signal.org/docs/specifications/xeddsa/. Firmware's variant derives the
// nonce prefix the way Ed25519 does rather than the way the spec does, which changes
// nothing for interoperability: both sides still verify as plain Ed25519 against the
// converted public key.

const (
	// XEdDSASignatureSize is the byte length of an XEdDSA signature.
	XEdDSASignatureSize = 64

	// xeddsaRandomSize is the length of the random value mixed into the nonce.
	xeddsaRandomSize = 32
)

// ErrInvalidKeyLength reports a key that is not 32 bytes.
var ErrInvalidKeyLength = errors.New("key must be 32 bytes")

// SignXEdDSA signs message with an X25519 private key, returning a 64-byte signature.
//
// The signature is randomized: signing the same message twice produces different bytes.
// That is deliberate, and matches firmware, which mixes fresh randomness into the nonce
// so a faulty or repeated nonce cannot expose the private key.
func SignXEdDSA(privateKey, message []byte) ([]byte, error) {
	random := make([]byte, xeddsaRandomSize)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("reading entropy: %w", err)
	}
	return signXEdDSA(privateKey, message, random)
}

// signXEdDSA is SignXEdDSA with the nonce randomness supplied, so tests can reproduce a
// known signature. Callers outside tests should use SignXEdDSA.
func signXEdDSA(privateKey, message, random []byte) ([]byte, error) {
	if len(privateKey) != PublicKeySize {
		return nil, ErrInvalidKeyLength
	}
	if len(random) != xeddsaRandomSize {
		return nil, fmt.Errorf("nonce randomness must be %d bytes, got %d", xeddsaRandomSize, len(random))
	}

	scalar, scalarBytes, publicKey := deriveEd25519Key(privateKey)

	// The nonce hash folds in a secret prefix, the message, and fresh randomness, so it
	// is unpredictable even if the randomness turns out to be poor.
	keyHash := sha512.Sum512(scalarBytes)
	nonceHash := sha512.New()
	nonceHash.Write(keyHash[32:])
	nonceHash.Write(message)
	nonceHash.Write(random)
	r, err := edwards25519.NewScalar().SetUniformBytes(nonceHash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("deriving nonce: %w", err)
	}

	signature := make([]byte, 0, XEdDSASignatureSize)
	signature = append(signature, new(edwards25519.Point).ScalarBaseMult(r).Bytes()...)

	challengeHash := sha512.New()
	challengeHash.Write(signature) // R
	challengeHash.Write(publicKey) // A
	challengeHash.Write(message)
	k, err := edwards25519.NewScalar().SetUniformBytes(challengeHash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("deriving challenge: %w", err)
	}

	// s = r + k*a
	s := edwards25519.NewScalar().MultiplyAdd(k, scalar, r)
	return append(signature, s.Bytes()...), nil
}

// VerifyXEdDSA reports whether signature is a valid XEdDSA signature over message by the
// holder of the X25519 private key matching publicKey. It returns false rather than an
// error for any malformed input, since a caller deciding whether to accept a packet
// treats every failure the same way.
func VerifyXEdDSA(publicKey, message, signature []byte) bool {
	if len(signature) != XEdDSASignatureSize {
		return false
	}
	edPublicKey, err := PublicKeyToEd25519(publicKey)
	if err != nil {
		return false
	}
	return ed25519.Verify(edPublicKey, message, signature)
}

// packetSigningBuffer lays out the bytes a packet signature covers: the sender, the
// packet id, and the port number, each little-endian, followed by the decoded payload.
//
// Binding the metadata is the point. Signing the payload alone would let an attacker
// replay it under a different id, reattribute it to another sender, or move it to a
// different port to have the receiver interpret it as something else.
func packetSigningBuffer(from, packetID uint32, portnum pb.PortNum, payload []byte) []byte {
	buf := make([]byte, 12, 12+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], from)
	binary.LittleEndian.PutUint32(buf[4:8], packetID)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(portnum))
	return append(buf, payload...)
}

// SignPacketData signs a packet's decoded payload together with the metadata that binds
// it to this sender, id, and port. The payload is the plaintext, signed before any
// encryption is applied.
func SignPacketData(privateKey []byte, from, packetID uint32, portnum pb.PortNum, payload []byte) ([]byte, error) {
	return SignXEdDSA(privateKey, packetSigningBuffer(from, packetID, portnum, payload))
}

// VerifyPacketData reports whether signature authenticates a packet's decoded payload as
// coming from the holder of publicKey, for this exact sender, id, and port.
func VerifyPacketData(publicKey []byte, from, packetID uint32, portnum pb.PortNum, payload, signature []byte) bool {
	return VerifyXEdDSA(publicKey, packetSigningBuffer(from, packetID, portnum, payload), signature)
}

// PublicKeyFromPrivate recovers the X25519 public key belonging to a private key, for
// callers that persist only the private half of an identity.
func PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	if len(privateKey) != PublicKeySize {
		return nil, ErrInvalidKeyLength
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("deriving public key: %w", err)
	}
	return publicKey, nil
}

// PublicKeyToEd25519 maps an X25519 public key onto the equivalent Ed25519 public key,
// so a signature can be checked against the identity key a node already advertises.
//
// The Montgomery form only carries the u coordinate, so the Edwards x coordinate cannot
// be recovered; XEdDSA resolves that by having signers normalize to a zero sign bit,
// which is why the bit is cleared unconditionally here rather than derived.
func PublicKeyToEd25519(publicKey []byte) ([]byte, error) {
	if len(publicKey) != PublicKeySize {
		return nil, ErrInvalidKeyLength
	}

	u, err := new(field.Element).SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	// Birational map from RFC 7748 section 4.1: y = (u - 1) / (u + 1).
	one := new(field.Element).One()
	numerator := new(field.Element).Subtract(u, one)
	denominator := new(field.Element).Add(u, one)
	y := new(field.Element).Multiply(numerator, new(field.Element).Invert(denominator))

	edPublicKey := y.Bytes()
	edPublicKey[31] &= 0x7F
	return edPublicKey, nil
}

// deriveEd25519Key turns an X25519 private key into the Ed25519 signing scalar, that
// scalar's canonical bytes, and the matching public key.
//
// A scalar and its negation produce points that differ only in sign, so exactly one of
// them encodes with a zero sign bit. Picking that one is what lets a verifier recover
// the public key from the u coordinate alone.
func deriveEd25519Key(privateKey []byte) (scalar *edwards25519.Scalar, scalarBytes, publicKey []byte) {
	// SetBytesWithClamping cannot fail on a 32-byte input, which the caller checked.
	scalar, _ = edwards25519.NewScalar().SetBytesWithClamping(privateKey)

	// Before any negation the scalar bytes are the clamped key itself, not its reduced
	// form; firmware hashes those exact bytes for the nonce prefix.
	scalarBytes = make([]byte, PublicKeySize)
	copy(scalarBytes, privateKey)
	scalarBytes[0] &= 0xF8
	scalarBytes[31] &= 0x7F
	scalarBytes[31] |= 0x40

	publicKey = new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	if publicKey[31]&0x80 != 0 {
		scalar.Negate(scalar)
		scalarBytes = scalar.Bytes()
		publicKey = new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	}
	return scalar, scalarBytes, publicKey
}
