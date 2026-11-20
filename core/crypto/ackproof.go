package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/encoding/protowire"
)

// AckProofSize is the length of Routing.ack_proof.
const AckProofSize = 8

// ackProofField is Routing.ack_proof's field number.
const ackProofField protowire.Number = 4

// ComputeAckProof derives firmware's pairwise ack proof (AckProof.h): HMAC-SHA256
// under the PKI shared secret over "ack" | from | to | request_id | routing, with
// the integers little-endian, truncated to AckProofSize. routing is the encoded
// Routing message without its ack_proof field, so an ack cannot be turned into a
// nak, and request_id stops a proof being moved onto another packet.
func ComputeAckProof(privateKey, peerPublicKey []byte, from, to, requestID uint32, routing []byte) ([]byte, error) {
	if len(privateKey) != PublicKeySize || len(peerPublicKey) != PublicKeySize {
		return nil, ErrInvalidKeyLength
	}
	key, err := sharedSecret(privateKey, peerPublicKey)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 3, 3+12)
	copy(header, "ack")
	header = binary.LittleEndian.AppendUint32(header, from)
	header = binary.LittleEndian.AppendUint32(header, to)
	header = binary.LittleEndian.AppendUint32(header, requestID)

	mac := hmac.New(sha256.New, key)
	mac.Write(header)
	mac.Write(routing)
	return mac.Sum(nil)[:AckProofSize], nil
}

// AttachAckProof appends a proof to an encoded Routing message, after the fields
// it covers, as firmware's ackProofAttachWithKey does.
func AttachAckProof(routing, privateKey, peerPublicKey []byte, from, to, requestID uint32) ([]byte, error) {
	proof, err := ComputeAckProof(privateKey, peerPublicKey, from, to, requestID, routing)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), routing...)
	out = protowire.AppendTag(out, ackProofField, protowire.BytesType)
	return protowire.AppendBytes(out, proof), nil
}

// HasAckProof reports whether an encoded Routing message carries a well-formed
// proof.
func HasAckProof(routing []byte) bool {
	_, _, err := extractAckProof(routing)
	return err == nil
}

// VerifyAckProof checks the proof on an encoded Routing message we received.
// peerPublicKey is the key of the node the ack claims to come from; nil gives
// NO_KEY when a proof is present. A missing or malformed proof is ABSENT, as in
// firmware, where a proof is advisory and its absence changes nothing.
func VerifyAckProof(routing, privateKey, peerPublicKey []byte, from, to, requestID uint32) pb.MeshPacket_AckProofStatus {
	claimed, without, err := extractAckProof(routing)
	if err != nil {
		return pb.MeshPacket_ACK_PROOF_ABSENT
	}
	if peerPublicKey == nil {
		return pb.MeshPacket_ACK_PROOF_NO_KEY
	}
	expected, err := ComputeAckProof(privateKey, peerPublicKey, from, to, requestID, without)
	if err != nil {
		return pb.MeshPacket_ACK_PROOF_NO_KEY
	}
	if !hmac.Equal(claimed, expected) {
		return pb.MeshPacket_ACK_PROOF_INVALID
	}
	return pb.MeshPacket_ACK_PROOF_VALID
}

var errNoAckProof = errors.New("no well-formed ack proof")

// extractAckProof returns the proof and the Routing bytes with its field
// removed. Like firmware's ackProofExtract, a proof of the wrong size, a second
// proof field, or bytes that do not parse count as no proof at all.
func extractAckProof(routing []byte) (proof, without []byte, err error) {
	start, end := -1, -1
	for off := 0; off < len(routing); {
		num, typ, n := protowire.ConsumeTag(routing[off:])
		if n < 0 {
			return nil, nil, errNoAckProof
		}
		m := protowire.ConsumeFieldValue(num, typ, routing[off+n:])
		if m < 0 {
			return nil, nil, errNoAckProof
		}
		if num == ackProofField && typ == protowire.BytesType {
			v, vn := protowire.ConsumeBytes(routing[off+n:])
			if start >= 0 || vn < 0 || len(v) != AckProofSize {
				return nil, nil, errNoAckProof
			}
			start, end = off, off+n+m
			proof = v
		}
		off += n + m
	}
	if start < 0 {
		return nil, nil, errNoAckProof
	}
	without = append(append([]byte(nil), routing[:start]...), routing[end:]...)
	return append([]byte(nil), proof...), without, nil
}
