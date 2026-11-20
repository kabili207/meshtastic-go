package mqtt

import (
	"testing"

	paho "github.com/eclipse/paho.mqtt.golang"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// fakeClient records subscriptions and publishes. Methods the transport does not
// call fall through to the nil embedded interface and panic, which flags them.
type fakeClient struct {
	paho.Client
	subscribed []string
	published  map[string][]byte
}

func (c *fakeClient) IsConnected() bool { return true }

func (c *fakeClient) Subscribe(topic string, _ byte, _ paho.MessageHandler) paho.Token {
	c.subscribed = append(c.subscribed, topic)
	return &paho.DummyToken{}
}

func (c *fakeClient) Publish(topic string, _ byte, _ bool, payload any) paho.Token {
	if c.published == nil {
		c.published = map[string][]byte{}
	}
	c.published[topic] = payload.([]byte)
	return &paho.DummyToken{}
}

func connectedTransport() (*Transport, *fakeClient) {
	tr := testTransport()
	c := &fakeClient{}
	tr.client = c
	tr.connected = true
	return tr, c
}

// Firmware subscribes to the PKI topic alongside its channels, since every
// PKI-encrypted packet is published there.
func TestSubscribesToPKITopic(t *testing.T) {
	tr, c := connectedTransport()
	tr.AddChannel("LongFast")
	tr.AddChannel("Other")

	want := []string{"msh/US/2/e/LongFast/+", "msh/US/2/e/PKI/+", "msh/US/2/e/Other/+"}
	if len(c.subscribed) != len(want) {
		t.Fatalf("subscribed to %v, want %v", c.subscribed, want)
	}
	for i := range want {
		if c.subscribed[i] != want[i] {
			t.Errorf("subscription %d = %q, want %q", i, c.subscribed[i], want[i])
		}
	}

	c.subscribed = nil
	tr.onConnected(nil)
	pki := 0
	for _, topic := range c.subscribed {
		if topic == "msh/US/2/e/PKI/+" {
			pki++
		}
	}
	if pki != 1 || len(c.subscribed) != 3 {
		t.Errorf("resubscribed to %v, want both channels and PKI once", c.subscribed)
	}
}

// Firmware's onSend publishes every PKI-encrypted packet under channel ID "PKI".
func TestSendPacketPKIUsesPKITopic(t *testing.T) {
	tr, c := connectedTransport()
	pkt := encryptedPacket()
	pkt.PkiEncrypted = true
	pkt.Channel = 0

	if err := tr.SendPacket("LongFast", pkt); err != nil {
		t.Fatal(err)
	}
	payload, ok := c.published["msh/US/2/e/PKI/"+selfNode.String()]
	if !ok {
		t.Fatalf("published to %v, want the PKI topic", c.published)
	}
	se := &pb.ServiceEnvelope{}
	if err := proto.Unmarshal(payload, se); err != nil {
		t.Fatal(err)
	}
	if se.ChannelId != PKIChannel {
		t.Errorf("envelope channel_id = %q, want %q", se.ChannelId, PKIChannel)
	}
}
