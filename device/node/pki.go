package node

import (
	"context"
	"fmt"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// hasPKI returns true if this node has PKI keys configured.
func (n *Node) hasPKI() bool {
	return len(n.cfg.PrivateKey) > 0 && len(n.cfg.PublicKey) > 0
}

// lookupPublicKey returns the X25519 public key for a remote node by checking
// the NodeDB. Returns nil if the node is unknown or has no public key.
func (n *Node) lookupPublicKey(id core.NodeID) []byte {
	if info := n.db.Get(id.Uint32()); info != nil && info.User != nil {
		if len(info.User.PublicKey) > 0 {
			return info.User.PublicKey
		}
	}
	return nil
}

// shouldTryPKI returns true if the packet should be attempted for PKI decryption.
// PKI is used for channel-0 unicast packets addressed to this node.
func (n *Node) shouldTryPKI(pkt *pb.MeshPacket) bool {
	if !n.hasPKI() {
		return false
	}
	if _, ok := pkt.PayloadVariant.(*pb.MeshPacket_Encrypted); !ok {
		return false
	}
	to := core.NodeID(pkt.To)
	return pkt.Channel == 0 &&
		pkt.To > 0 &&
		!to.IsBroadcast() &&
		to == n.cfg.NodeID
}

// tryDecryptPKI attempts to decrypt a PKI-encrypted packet using this node's
// private key and the sender's public key from the NodeDB.
func (n *Node) tryDecryptPKI(pkt *pb.MeshPacket) (*pb.Data, error) {
	from := core.NodeID(pkt.From)

	pubKey := n.lookupPublicKey(from)
	if pubKey == nil {
		return nil, fmt.Errorf("no public key for %s", from)
	}

	return crypto.TryDecodePKI(pkt, pubKey, n.cfg.PrivateKey)
}

// SendData sends a data payload to a recipient. Unicasts are PKI-encrypted
// whenever firmware would (see usesPKI), and fail with ErrNoPublicKey when the
// recipient's key is unknown. requirePKI also fails a send that would otherwise
// go out on a channel key.
func (n *Node) SendData(ctx context.Context, to core.NodeID, data *pb.Data, requirePKI bool) error {
	return n.base.sendPacketWith(ctx, &pb.MeshPacket{
		From:           n.cfg.NodeID.Uint32(),
		To:             to.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}, sendOptions{usePKI: requirePKI})
}
