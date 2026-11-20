package crypto

import (
	"bytes"
	"testing"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/encoding/protowire"
)

// These mirror firmware's test_ack_proof cases.

type keypair struct{ pub, priv []byte }

func newKeypair(t *testing.T) keypair {
	t.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return keypair{pub, priv}
}

var routingNone = []byte{0x18, 0x00} // error_reason = NONE

const (
	ackFrom   = uint32(0xB0B)
	ackTo     = uint32(0xA11CE)
	requestID = uint32(0x1234)
)

// Recipient B acks sender A's packet; A verifies with its own key and B's.
func TestAckProofRoundTrip(t *testing.T) {
	a, b := newKeypair(t), newKeypair(t)
	routing, err := AttachAckProof(routingNone, b.priv, a.pub, ackFrom, ackTo, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(routing, routingNone) || len(routing) != len(routingNone)+2+AckProofSize {
		t.Fatalf("proof not appended after the Routing fields: %x", routing)
	}
	if got := VerifyAckProof(routing, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_VALID {
		t.Errorf("verify = %v, want VALID", got)
	}
}

func TestAckProofBindings(t *testing.T) {
	a, b, c := newKeypair(t), newKeypair(t), newKeypair(t)
	routing, _ := AttachAckProof(routingNone, b.priv, a.pub, ackFrom, ackTo, requestID)
	nak, _ := AttachAckProof([]byte{0x18, 0x02}, b.priv, a.pub, ackFrom, ackTo, requestID)
	asNak := append([]byte{0x18, 0x02}, routing[len(routingNone):]...)

	tests := []struct {
		name              string
		routing, peer     []byte
		from, to, request uint32
	}{
		{"other request id", routing, b.pub, ackFrom, ackTo, requestID + 1},
		{"reversed direction", routing, b.pub, ackTo, ackFrom, requestID},
		{"third peer's key", routing, c.pub, ackFrom, ackTo, requestID},
		{"ack proof moved onto a nak", asNak, b.pub, ackFrom, ackTo, requestID},
	}
	for _, tt := range tests {
		if got := VerifyAckProof(tt.routing, a.priv, tt.peer, tt.from, tt.to, tt.request); got != pb.MeshPacket_ACK_PROOF_INVALID {
			t.Errorf("%s: verify = %v, want INVALID", tt.name, got)
		}
	}
	if got := VerifyAckProof(nak, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_VALID {
		t.Errorf("a proven nak: verify = %v, want VALID", got)
	}
}

func TestAckProofVerdicts(t *testing.T) {
	a, b := newKeypair(t), newKeypair(t)
	routing, _ := AttachAckProof(routingNone, b.priv, a.pub, ackFrom, ackTo, requestID)

	if got := VerifyAckProof(routingNone, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_ABSENT {
		t.Errorf("no proof: %v, want ABSENT", got)
	}
	if got := VerifyAckProof(routing, a.priv, nil, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_NO_KEY {
		t.Errorf("no peer key: %v, want NO_KEY", got)
	}

	tampered := bytes.Clone(routing)
	tampered[len(tampered)-1] ^= 1
	if got := VerifyAckProof(tampered, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_INVALID {
		t.Errorf("tampered proof: %v, want INVALID", got)
	}
}

// A proof of the wrong size, or a second proof field, reads as no proof.
func TestAckProofMalformedIsAbsent(t *testing.T) {
	a, b := newKeypair(t), newKeypair(t)
	routing, _ := AttachAckProof(routingNone, b.priv, a.pub, ackFrom, ackTo, requestID)

	short := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(routingNone), ackProofField, protowire.BytesType), make([]byte, 7))
	duplicate := append(bytes.Clone(routing), routing[len(routingNone):]...)
	for name, r := range map[string][]byte{"7-byte proof": short, "two proofs": duplicate, "truncated": routing[:len(routing)-1]} {
		if got := VerifyAckProof(r, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_ABSENT {
			t.Errorf("%s: %v, want ABSENT", name, got)
		}
	}
}

// Every other Routing field is covered, including ones this build does not know.
func TestAckProofCoversUnknownFields(t *testing.T) {
	a, b := newKeypair(t), newKeypair(t)
	extra := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(routingNone), 15, protowire.BytesType), []byte{0x11, 0x22, 0x33})
	routing, _ := AttachAckProof(extra, b.priv, a.pub, ackFrom, ackTo, requestID)
	if got := VerifyAckProof(routing, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_VALID {
		t.Fatalf("with an unknown field: %v, want VALID", got)
	}
	routing[len(extra)-1] ^= 1
	if got := VerifyAckProof(routing, a.priv, b.pub, ackFrom, ackTo, requestID); got != pb.MeshPacket_ACK_PROOF_INVALID {
		t.Errorf("unknown field altered: %v, want INVALID", got)
	}
}
