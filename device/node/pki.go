package node

import (
	"context"
	"fmt"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
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

// SendData sends a data payload to a recipient. If usePKI is true and PKI
// keys are available for both sender and recipient, the packet is sent with
// Curve25519 encryption. Otherwise it falls back to PSK channel encryption
// on the primary channel.
func (n *Node) SendData(ctx context.Context, to core.NodeID, data *pb.Data, usePKI bool) error {
	if usePKI {
		err := n.sendPKIPacket(ctx, to, data)
		if err == nil {
			return nil
		}
		n.base.log.Debug("PKI send failed, falling back to PSK", "to", to, "error", err)
	}
	return n.base.sendPacket(ctx, &pb.MeshPacket{
		From: n.cfg.NodeID.Uint32(),
		To:   to.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: data,
		},
	}, "")
}

// sendPKIPacket sends a PKI-encrypted packet to a specific recipient using
// this node's private key and the recipient's public key from the NodeDB.
func (n *Node) sendPKIPacket(ctx context.Context, to core.NodeID, data *pb.Data) error {
	if !n.hasPKI() {
		return fmt.Errorf("PKI not configured")
	}
	pubKey := n.lookupPublicKey(to)
	if pubKey == nil {
		return fmt.Errorf("no public key for recipient %s", to)
	}

	plaintext, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling data: %w", err)
	}

	packetID := n.base.packetIDs.next()
	encrypted, err := crypto.EncryptCurve25519(plaintext, n.cfg.PrivateKey, pubKey, packetID, n.cfg.NodeID.Uint32())
	if err != nil {
		return fmt.Errorf("PKI encryption: %w", err)
	}

	pkt := &pb.MeshPacket{
		Id:           packetID,
		From:         n.cfg.NodeID.Uint32(),
		To:           to.Uint32(),
		Channel:      0,
		PkiEncrypted: true,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: encrypted,
		},
	}
	n.base.applyPacketDefaults(pkt)

	n.base.sendMu.Lock()
	defer n.base.sendMu.Unlock()
	if !n.base.lastSend.IsZero() {
		if elapsed := time.Since(n.base.lastSend); elapsed < sendDelay {
			time.Sleep(sendDelay - elapsed)
		}
	}
	n.base.lastSend = time.Now()

	// PKI packets use channel 0; send on primary channel's transport topic
	return n.base.transport.SendPacket(n.base.primaryChannel, pkt)
}
