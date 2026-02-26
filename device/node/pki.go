package node

import (
	"context"
	"fmt"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// shouldTryPKI returns true if the packet should be attempted for PKI decryption.
// PKI is used for channel-0 unicast packets addressed to a node we manage.
func (n *Node) shouldTryPKI(pkt *pb.MeshPacket) bool {
	if n.cfg.PrivateKeyFunc == nil || n.cfg.PublicKeyFunc == nil {
		return false
	}
	if _, ok := pkt.PayloadVariant.(*pb.MeshPacket_Encrypted); !ok {
		return false
	}
	to := core.NodeID(pkt.To)
	return pkt.Channel == 0 &&
		pkt.To > 0 &&
		!to.IsBroadcast() &&
		n.cfg.PrivateKeyFunc(to) != nil
}

// tryDecryptPKI attempts to decrypt a PKI-encrypted packet using the managed
// node's private key and the sender's public key.
func (n *Node) tryDecryptPKI(pkt *pb.MeshPacket) (*pb.Data, error) {
	to := core.NodeID(pkt.To)
	from := core.NodeID(pkt.From)

	privKey := n.cfg.PrivateKeyFunc(to)
	if privKey == nil {
		return nil, fmt.Errorf("no private key for %s", to)
	}
	pubKey := n.cfg.PublicKeyFunc(from)
	if pubKey == nil {
		return nil, fmt.Errorf("no public key for %s", from)
	}

	return crypto.TryDecodePKI(pkt, pubKey, privKey)
}

// SendPKIPacket sends a PKI-encrypted packet from a managed node to a
// specific recipient. The sender's private key is fetched via PrivateKeyFunc
// and the recipient's public key via PublicKeyFunc.
func (n *Node) SendPKIPacket(ctx context.Context, from, to core.NodeID, data *pb.Data) error {
	if n.cfg.PrivateKeyFunc == nil || n.cfg.PublicKeyFunc == nil {
		return fmt.Errorf("PKI not configured")
	}
	privKey := n.cfg.PrivateKeyFunc(from)
	if privKey == nil {
		return fmt.Errorf("no private key for sender %s", from)
	}
	pubKey := n.cfg.PublicKeyFunc(to)
	if pubKey == nil {
		return fmt.Errorf("no public key for recipient %s", to)
	}

	plaintext, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling data: %w", err)
	}

	packetID := n.packetIDs.next()
	encrypted, err := crypto.EncryptCurve25519(plaintext, privKey, pubKey, packetID, from.Uint32())
	if err != nil {
		return fmt.Errorf("PKI encryption: %w", err)
	}

	pkt := &pb.MeshPacket{
		Id:           packetID,
		From:         from.Uint32(),
		To:           to.Uint32(),
		Channel:      0,
		PkiEncrypted: true,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: encrypted,
		},
	}

	// PKI packets use channel 0; send on primary channel's transport topic
	return n.transport.SendPacket(n.cfg.Channels.Settings[0].Name, pkt)
}
