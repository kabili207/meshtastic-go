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

// signOutbound signs a Data we originate, choosing packets the way firmware's
// perhapsEncode does under BALANCED and STRICT. We own signing for our own packets,
// so any signature a caller preset is discarded first: a stale one would hard-fail
// verification at every receiver that knows our key.
//
// Unlike firmware, COMPATIBLE signs too. Every policy accepts a valid signature, and
// signing is what lets peers bind our identities to their keys. A PKI or AEAD
// packet is authenticated by its encryption and never signed.
func (b *baseNode) signOutbound(data *pb.Data, from, packetID uint32, to core.NodeID, encAuthenticated bool) {
	data.XeddsaSignature = nil
	if encAuthenticated || b.privateKeyFor == nil || !signableOutbound(data.Portnum, to, b.licensed) {
		return
	}
	key := b.privateKeyFor(core.NodeID(from))
	if key == nil {
		// A packet that should have been signed but was not: peers that know this
		// identity as a signer will drop it, and new peers will never mark it verified.
		b.log.Warn("no private key to sign outbound packet", "from", core.NodeID(from), "packetID", packetID, "portnum", data.Portnum)
		return
	}
	if !signedDataFits(data) {
		b.log.Debug("outbound packet too large to sign", "from", core.NodeID(from), "packetID", packetID, "portnum", data.Portnum)
		return
	}
	sig, err := crypto.SignPacketData(key, from, packetID, to.Uint32(), data)
	if err != nil {
		b.log.Warn("signing packet", "packetID", packetID, "error", err)
		return
	}
	data.XeddsaSignature = sig
	b.log.Debug("signed outbound packet", "from", core.NodeID(from), "packetID", packetID, "portnum", data.Portnum)
}

// signableOutbound reports whether firmware would sign a non-PKI packet. NodeInfo
// and position are signed even when unicast, since they never travel under PKI and
// a NodeInfo carries the key peers will use. Licensed nodes have no PKI, so they sign
// unicasts too, except acks. A traceroute is never signed: every hop rewrites it.
func signableOutbound(portnum pb.PortNum, to core.NodeID, licensed bool) bool {
	if portnum == pb.PortNum_TRACEROUTE_APP {
		return false
	}
	return to.IsBroadcast() ||
		portnum == pb.PortNum_NODEINFO_APP ||
		portnum == pb.PortNum_POSITION_APP ||
		(licensed && portnum != pb.PortNum_ROUTING_APP)
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
// from our own verification. An AEAD channel's tag authenticates every packet, so
// STRICT does not apply there, though a bad signature still drops the packet.
func (b *baseNode) checkSignaturePolicy(pkt *pb.MeshPacket, data *pb.Data, isPKI, aead bool) (signed, accept bool) {
	pkt.XeddsaSigned = false
	// Every hop rewrites a traceroute, so a signature on one cannot verify past the
	// first hop. Ignore it, and never require one.
	if data.Portnum == pb.PortNum_TRACEROUTE_APP {
		return false, true
	}
	sig := data.XeddsaSignature
	strict := b.signaturePolicy == pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_STRICT && !aead
	from := core.NodeID(pkt.From)

	switch {
	case len(sig) == crypto.XEdDSASignatureSize:
		// Authoritative keys only. Verifying against a key learned from an unsigned
		// NodeInfo would let a planted key mark its own node a signer.
		if key := b.lookupPublicKey(from); key != nil {
			if !crypto.VerifyPacketData(key, pkt.From, pkt.Id, pkt.To, data, sig) {
				b.log.Warn("XEdDSA signature failed to verify", "from", from, "packetID", pkt.Id)
				return false, false
			}
			if !signedNodeInfoConsistent(pkt.From, data, key) {
				b.log.Warn("signed NodeInfo claims a key that did not sign it", "from", from, "packetID", pkt.Id)
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
		return false, !strict

	case len(sig) != 0:
		// Honest senders emit exactly 0 or 64 bytes.
		b.log.Warn("malformed XEdDSA signature", "from", from, "size", len(sig))
		return false, false

	default:
		// Only STRICT drops a packet for being unsigned; pinIdentity guards a known
		// signer's identity under BALANCED. Acks carry their own proof, and key
		// verification runs before either side has a key to sign with.
		if strict && !isPKI &&
			data.Portnum != pb.PortNum_ROUTING_APP &&
			data.Portnum != pb.PortNum_KEY_VERIFICATION_APP {
			return false, false
		}
		return false, true
	}
}

// signedNodeInfoConsistent reports whether a NodeInfo verified against a stored key
// claims that same key, bound to the sender's ID. Without this a node could sign a
// NodeInfo that swaps in someone else's key. A keyless or undecodable payload has
// nothing to compare, and pinIdentity handles it.
func signedNodeInfoConsistent(from uint32, data *pb.Data, signerKey []byte) bool {
	if data.Portnum != pb.PortNum_NODEINFO_APP {
		return true
	}
	user := &pb.User{}
	if err := proto.Unmarshal(data.Payload, user); err != nil || len(user.PublicKey) != crypto.PublicKeySize {
		return true
	}
	return bytes.Equal(user.PublicKey, signerKey) && core.NodeID(from).MatchesPublicKey(user.PublicKey)
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
		!crypto.VerifyPacketData(key, pkt.From, pkt.Id, pkt.To, data, data.XeddsaSignature) {
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

// pinIdentity applies firmware's identity-write rules (NodeDB::updateUser) before a
// NodeInfo is stored, reporting whether the update should go ahead:
//   - under BALANCED and STRICT, a node known to sign may only change its identity
//     through a signed NodeInfo, except on an AEAD channel
//   - a NodeInfo advertising one of our own keys is refused
//   - once we hold a key for a node, a NodeInfo carrying a different key, or none,
//     is refused outright, names included
func (b *baseNode) pinIdentity(from uint32, user *pb.User, signed, aead bool) bool {
	if b.db == nil {
		return true
	}
	existing := b.db.Get(from)
	if !signed && !aead && existing != nil && existing.HasXeddsaSigned &&
		b.signaturePolicy != pb.Config_SecurityConfig_PACKET_SIGNATURE_POLICY_COMPATIBLE {
		b.log.Debug("refusing unsigned NodeInfo from a node that signs", "from", core.NodeID(from))
		return false
	}
	if b.isOwnPublicKey(from, user.PublicKey) {
		b.log.Warn("remote node advertised one of our public keys", "from", core.NodeID(from))
		return false
	}
	if existing == nil || existing.User == nil {
		return true
	}
	if held := existing.User.PublicKey; len(held) == crypto.PublicKeySize && !bytes.Equal(held, user.PublicKey) {
		b.log.Warn("NodeInfo public key does not match the one held", "from", core.NodeID(from))
		return false
	}
	return true
}

// isOwnPublicKey reports whether key belongs to an identity we hold the private key
// for, advertised by some other node. Our node IDs derive from our keys, so the key
// names the identity to check.
func (b *baseNode) isOwnPublicKey(from uint32, key []byte) bool {
	if b.privateKeyFor == nil || len(key) != crypto.PublicKeySize {
		return false
	}
	id, err := core.NodeIDFromPublicKey(key)
	if err != nil || id.Uint32() == from {
		return false
	}
	priv := b.privateKeyFor(id)
	if priv == nil {
		return false
	}
	ours, err := crypto.PublicKeyFromPrivate(priv)
	return err == nil && bytes.Equal(ours, key)
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

func (b *baseNode) markSigner(from uint32) {
	if b.db == nil {
		return
	}
	b.db.Update(from, func(info *pb.NodeInfo) { info.HasXeddsaSigned = true })
}
