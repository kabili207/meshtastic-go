package node

import (
	"context"
	"errors"
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

// Mirrors firmware's wouldEncryptWithPKC port and destination exclusions.
func TestUsesPKI(t *testing.T) {
	const peer = core.NodeID(0xAA)
	tests := []struct {
		portnum  pb.PortNum
		to       core.NodeID
		licensed bool
		want     bool
	}{
		{pb.PortNum_TEXT_MESSAGE_APP, peer, false, true},
		{pb.PortNum_TELEMETRY_APP, peer, false, true},
		{pb.PortNum_WAYPOINT_APP, peer, false, true},
		{pb.PortNum_TEXT_MESSAGE_APP, core.BroadcastNodeID, false, false},
		{pb.PortNum_TRACEROUTE_APP, peer, false, false},
		{pb.PortNum_NODEINFO_APP, peer, false, false},
		{pb.PortNum_ROUTING_APP, peer, false, false},
		{pb.PortNum_POSITION_APP, peer, false, false},
		{pb.PortNum_TEXT_MESSAGE_APP, peer, true, false},
	}
	for _, tt := range tests {
		if got := usesPKI(tt.portnum, tt.to, tt.licensed); got != tt.want {
			t.Errorf("usesPKI(%v, %v, licensed=%v) = %v, want %v", tt.portnum, tt.to, tt.licensed, got, tt.want)
		}
	}
}

// pkiNode is a node with its own identity that knows peer's key.
func pkiNode(t *testing.T, mt *mockTransport, peer testIdentity) (*Node, testIdentity) {
	t.Helper()
	var events []any
	n, self := signingNode(t, mt, 0, &events)
	n.NodeDB().Update(peer.id.Uint32(), func(info *pb.NodeInfo) { info.User = &pb.User{PublicKey: peer.pub} })
	return n, self
}

// A text DM goes out under PKI by default, with the send options intact.
func TestSendTextDMUsesPKI(t *testing.T) {
	mt := newMockTransport()
	peer := newIdentity(t, 0x22)
	n, self := pkiNode(t, mt, peer)

	if err := n.SendText(context.Background(), peer.id, "secret", WithWantAck(), WithAutomation()); err != nil {
		t.Fatal(err)
	}
	sent := mt.lastSent().packet
	if !sent.PkiEncrypted || sent.Channel != 0 {
		t.Fatalf("PkiEncrypted %v, channel %d; want a PKI packet on channel 0", sent.PkiEncrypted, sent.Channel)
	}
	data, err := crypto.TryDecodePKI(sent, self.pub, peer.priv)
	if err != nil {
		t.Fatalf("peer could not decrypt the DM: %v", err)
	}
	if string(data.Payload) != "secret" {
		t.Errorf("payload %q, want %q", data.Payload, "secret")
	}
	if !sent.WantAck {
		t.Error("want_ack was dropped from a PKI send")
	}
	if data.GetBitfield()&bitfieldIsAutomation == 0 {
		t.Error("the automation bit was dropped from a PKI send")
	}
}

// Firmware refuses a DM it cannot PKI-encrypt rather than sending one receivers
// will reject as a legacy DM.
func TestSendTextDMWithoutKeyFails(t *testing.T) {
	mt := newMockTransport()
	var events []any
	n, _ := signingNode(t, mt, 0, &events)

	err := n.SendText(context.Background(), 0xAA, "dm")
	if !errors.Is(err, ErrNoPublicKey) {
		t.Errorf("err = %v, want ErrNoPublicKey", err)
	}
	if mt.sentCount() != 0 {
		t.Error("a DM was sent without the recipient's key")
	}
}

// Ports firmware never PKI-encrypts still use the channel key on a unicast.
func TestUnicastExcludedPortsUseChannelKey(t *testing.T) {
	mt := newMockTransport()
	peer := newIdentity(t, 0x22)
	n, _ := pkiNode(t, mt, peer)

	if err := n.SendData(context.Background(), peer.id, &pb.Data{Portnum: pb.PortNum_POSITION_APP}, false); err != nil {
		t.Fatal(err)
	}
	sent, data := decryptSent(t, mt)
	if sent.PkiEncrypted || data.Portnum != pb.PortNum_POSITION_APP {
		t.Error("a unicast position was not sent on the channel key")
	}
}

func TestRequirePKI(t *testing.T) {
	mt := newMockTransport()
	peer := newIdentity(t, 0x22)
	n, _ := pkiNode(t, mt, peer)

	err := n.SendData(context.Background(), core.BroadcastNodeID, &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP}, true)
	if !errors.Is(err, ErrPKIUnavailable) {
		t.Errorf("broadcast with PKI required: err = %v, want ErrPKIUnavailable", err)
	}

	unkeyed := newTestNode(t, newMockTransport())
	err = unkeyed.SendText(context.Background(), peer.id, "dm", WithPKI())
	if !errors.Is(err, ErrPKIUnavailable) {
		t.Errorf("node without a private key: err = %v, want ErrPKIUnavailable", err)
	}
}

// A node without keys has no PKI, as firmware without a private key, so its DMs
// still go out on the channel key.
func TestNodeWithoutKeysSendsDMOnChannel(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)
	if err := n.SendText(context.Background(), 0xAA, "dm"); err != nil {
		t.Fatal(err)
	}
	if sent, _ := decryptSent(t, mt); sent.PkiEncrypted {
		t.Error("a node without keys sent a PKI packet")
	}
}

func TestBridgeTextDMUsesPKI(t *testing.T) {
	mt := newMockTransport()
	self := newIdentity(t, 0x11)
	peer := newIdentity(t, 0x22)
	b := newTestBridge(t, mt, func(c *BridgeConfig) {
		c.NodeID = self.id
		c.IsManagedNode = func(id core.NodeID) bool { return id == self.id }
		c.PrivateKeyForNode = func(id core.NodeID) []byte {
			if id == self.id {
				return self.priv
			}
			return nil
		}
		c.PublicKeyForNode = func(id core.NodeID) []byte {
			switch id {
			case self.id:
				return self.pub
			case peer.id:
				return peer.pub
			}
			return nil
		}
	})

	if _, err := b.SendTextAs(context.Background(), self.id, peer.id, "secret"); err != nil {
		t.Fatal(err)
	}
	sent := mt.lastSent().packet
	if _, err := crypto.TryDecodePKI(sent, self.pub, peer.priv); err != nil {
		t.Fatalf("bridge DM was not PKI-encrypted to the peer: %v", err)
	}

	_, err := b.SendTextAs(context.Background(), self.id, 0xAA, "dm")
	if !errors.Is(err, ErrNoPublicKey) {
		t.Errorf("DM to an unknown key: err = %v, want ErrNoPublicKey", err)
	}
}

// pskPacket encrypts data on the node's primary channel, as a peer would.
func pskPacket(t *testing.T, n *Node, from, to core.NodeID, id uint32, data *pb.Data) transport.NetworkPacket {
	t.Helper()
	raw, err := proto.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.XOR(raw, n.base.primary.GetKeyBytes(), id, from.Uint32())
	if err != nil {
		t.Fatal(err)
	}
	return transport.NetworkPacket{
		Channel: n.base.primary.GetName(),
		Packet: &pb.MeshPacket{
			Id:             id,
			From:           from.Uint32(),
			To:             to.Uint32(),
			Channel:        n.base.primary.GetHash(),
			PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: enc},
		},
	}
}

// Firmware rejects a channel-encrypted text DM addressed to it ("Rejecting legacy
// DM"), unless it has no PKI to offer instead.
func TestReceiveLegacyDM(t *testing.T) {
	dm := &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("legacy")}

	t.Run("rejected with PKI", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n, _ := signingNode(t, mt, 0, &events)
		inject(n, mt, pskPacket(t, n, 0xAA, n.cfg.NodeID, 100, dm))
		if len(textEvents(events)) != 0 {
			t.Error("a channel-encrypted DM was accepted")
		}
		inject(n, mt, pskPacket(t, n, 0xAA, core.BroadcastNodeID, 101, dm))
		if len(textEvents(events)) != 1 {
			t.Error("a channel-encrypted broadcast was rejected")
		}
	})

	t.Run("accepted without PKI", func(t *testing.T) {
		mt := newMockTransport()
		var events []any
		n := newTestNode(t, mt, func(c *Config) {
			c.EventHandlers = []event.Handler{func(evt any) { events = append(events, evt) }}
		})
		inject(n, mt, pskPacket(t, n, 0xAA, n.cfg.NodeID, 102, dm))
		if len(textEvents(events)) != 1 {
			t.Error("a node without keys rejected a channel-encrypted DM")
		}
	})
}
