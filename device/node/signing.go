package node

import (
	"bytes"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// XEdDSA packet signing, mirroring firmware's perhapsEncode on the way out and
// checkXeddsaReceivePolicy on the way in. See docs/upgrade-2.8.md, phase 3.

// signOutbound signs a Data we originate, when firmware would. We own signing for
// our own packets, so any signature a caller preset is discarded first: a stale one
// would hard-fail verification at every receiver that knows our key.
//
// Firmware signs non-PKI broadcasts, and unicasts too when licensed, since licensed
// traffic stays plaintext. It signs only when the signed encoding still fits the
// radio frame, checked on the exact encoded size rather than a payload heuristic.
func (b *baseNode) signOutbound(data *pb.Data, from, packetID uint32, to core.NodeID, pki bool) {
	data.XeddsaSignature = nil
	if pki || !(b.licensed || to.IsBroadcast()) || b.privateKeyFor == nil {
		return
	}
	key := b.privateKeyFor(core.NodeID(from))
	if key == nil {
		// A broadcast that should have been signed but was not: peers that know this
		// identity as a signer will drop it, and new peers will never mark it verified.
		b.log.Warn("no private key to sign outbound packet", "from", core.NodeID(from), "packetID", packetID, "portnum", data.Portnum)
		return
	}
	if !signedDataFits(data) {
		b.log.Debug("outbound packet too large to sign", "from", core.NodeID(from), "packetID", packetID, "portnum", data.Portnum)
		return
	}
	sig, err := crypto.SignPacketData(key, from, packetID, data.Portnum, data.Payload)
	if err != nil {
		b.log.Warn("signing packet", "packetID", packetID, "error", err)
		return
	}
	data.XeddsaSignature = sig
	b.log.Debug("signed outbound packet", "from", core.NodeID(from), "packetID", packetID, "portnum", data.Portnum)
}

// signedDataFits reports whether data, with a signature attached, still fits a
// LoRa frame alongside the packet header.
func signedDataFits(data *pb.Data) bool {
	sized := proto.Clone(data).(*pb.Data)
	sized.XeddsaSignature = make([]byte, crypto.XEdDSASignatureSize)
	return proto.Size(sized)+core.LoraHeaderLength <= core.MaxLoraPayload
}

// checkSignaturePolicy decides whether a decoded packet is accepted under the
// configured policy, and whether it carried a signature we verified. It never
// trusts an inbound xeddsa_signed flag: the packet's flag is cleared and set only
// from our own verification.
func (b *baseNode) checkSignaturePolicy(pkt *pb.MeshPacket, data *pb.Data, isPKI bool) (signed, accept bool) {
	pkt.XeddsaSigned = false
	sig := data.XeddsaSignature
	policy := b.signaturePolicy
	from := core.NodeID(pkt.From)

	switch {
	case len(sig) == crypto.XEdDSASignatureSize:
		// Authoritative keys only. Verifying against a key learned from an unsigned
		// NodeInfo would let a planted key mark its own node a signer.
		if key := b.lookupPublicKey(from); key != nil {
			if !crypto.VerifyPacketData(key, pkt.From, pkt.Id, data.Portnum, data.Payload, sig) {
				b.log.Warn("XEdDSA signature failed to verify", "from", from, "packetID", pkt.Id)
				return false, false
			}
			b.markSigner(pkt.From)
			pkt.XeddsaSigned = true
			return true, true
		}
		switch b.verifyFirstContactNodeInfo(pkt, data) {
		case bootstrapVerified:
			pkt.XeddsaSigned = true
			return true, true
		case bootstrapInvalid:
			b.log.Warn("invalid first-contact XEdDSA NodeInfo", "from", from, "packetID", pkt.Id)
			return false, false
		}
		// Signed, but we hold no key to check it against.
		return false, policy != pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT

	case len(sig) != 0:
		// Honest senders emit exactly 0 or 64 bytes. A partial signature is dropped
		// rather than treated as unsigned: its bytes would otherwise inflate the size
		// estimate below and let a forged broadcast dodge the downgrade drop.
		b.log.Warn("malformed XEdDSA signature", "from", from, "size", len(sig))
		return false, false

	default:
		if isPKI {
			return false, true
		}
		switch policy {
		case pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT:
			return false, false
		case pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_BALANCED:
			// Reject only what a signer always signs: non-PKI broadcasts whose signed
			// encoding would have fit, plus unicasts when licensed. Mirrors signOutbound.
			if b.isKnownSigner(pkt.From) && (core.NodeID(pkt.To).IsBroadcast() || b.licensed) {
				if canonicalSignableSize(data)+crypto.XEdDSASignatureFieldBytes+core.LoraHeaderLength <= core.MaxLoraPayload {
					b.log.Warn("dropping unsigned packet from a node that previously signed", "from", from)
					return false, false
				}
			}
			return false, true
		default:
			return false, true
		}
	}
}

// canonicalSignableSize sizes a Data the way the sender's signedDataFits gate would
// have, with padding stripped. Unknown fields inside a typed payload survive in its
// length and would otherwise let a forger inflate an unsigned broadcast past the
// signable budget, making it look like the sender legitimately could not sign.
func canonicalSignableSize(data *pb.Data) int {
	var inner proto.Message
	switch data.Portnum {
	case pb.PortNum_POSITION_APP:
		inner = &pb.Position{}
	case pb.PortNum_TELEMETRY_APP:
		inner = &pb.Telemetry{}
	case pb.PortNum_WAYPOINT_APP:
		inner = &pb.Waypoint{}
	case pb.PortNum_NODEINFO_APP:
		inner = &pb.User{}
	default:
		return proto.Size(data)
	}

	opts := proto.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(data.Payload, inner); err != nil {
		return proto.Size(data)
	}
	canonical := proto.Size(inner)
	if canonical > len(data.Payload) {
		return proto.Size(data)
	}
	// Only the length matters when sizing a bytes field.
	trimmed := proto.Clone(data).(*pb.Data)
	trimmed.Payload = data.Payload[:canonical]
	return proto.Size(trimmed)
}

type bootstrapResult int

const (
	bootstrapNotApplicable bootstrapResult = iota
	bootstrapVerified
	bootstrapInvalid
)

// verifyFirstContactNodeInfo lets a node we have never heard from introduce itself
// with a signed NodeInfo. The carried key must derive the claimed sender, so a node
// cannot introduce itself under an ID it does not own, and the signature must verify
// under that key. On success the key is stored and the node is marked a signer.
func (b *baseNode) verifyFirstContactNodeInfo(pkt *pb.MeshPacket, data *pb.Data) bootstrapResult {
	if data.Portnum != pb.PortNum_NODEINFO_APP {
		return bootstrapNotApplicable
	}
	user := &pb.User{}
	if err := proto.Unmarshal(data.Payload, user); err != nil {
		return bootstrapInvalid
	}
	key := user.PublicKey
	if !core.NodeID(pkt.From).MatchesPublicKey(key) ||
		!crypto.VerifyPacketData(key, pkt.From, pkt.Id, data.Portnum, data.Payload, data.XeddsaSignature) {
		return bootstrapInvalid
	}
	if b.db == nil {
		return bootstrapInvalid
	}
	b.db.Update(pkt.From, func(info *pb.NodeInfo) {
		if info.User == nil {
			info.User = &pb.User{}
		}
		info.User.PublicKey = bytes.Clone(key)
		info.HasXeddsaSigned = true
	})
	return bootstrapVerified
}

// pinIdentity applies firmware's identity-write rules before a NodeInfo is stored,
// reporting whether the update should go ahead. An unsigned NodeInfo may never
// replace a public key we already hold, and a node known to sign may only change
// its identity through a signed NodeInfo. user may be adjusted in place.
func (b *baseNode) pinIdentity(from uint32, user *pb.User, signed bool) bool {
	if signed || b.db == nil {
		return true
	}
	existing := b.db.Get(from)
	if existing == nil || existing.User == nil {
		return true
	}
	if existing.HasXeddsaSigned {
		return false
	}
	held := existing.User.PublicKey
	if len(held) == crypto.PublicKeySize && !bytes.Equal(held, user.PublicKey) {
		user.PublicKey = bytes.Clone(held)
	}
	return true
}

func (b *baseNode) lookupPublicKey(id core.NodeID) []byte {
	if b.publicKeyFor == nil {
		return nil
	}
	key := b.publicKeyFor(id)
	if len(key) != crypto.PublicKeySize {
		return nil
	}
	return key
}

func (b *baseNode) isKnownSigner(from uint32) bool {
	if b.db == nil {
		return false
	}
	info := b.db.Get(from)
	return info != nil && info.HasXeddsaSigned
}

func (b *baseNode) markSigner(from uint32) {
	if b.db == nil {
		return
	}
	b.db.Update(from, func(info *pb.NodeInfo) { info.HasXeddsaSigned = true })
}
