package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/device/event"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

// mockTransport implements raw.RawTransport for testing.
type mockTransport struct {
	mu        sync.Mutex
	connected bool
	sent      []sentPacket
	handler   transport.PacketHandler
}

type sentPacket struct {
	channel string
	packet  *pb.MeshPacket
}

func newMockTransport() *mockTransport {
	return &mockTransport{connected: true}
}

func (m *mockTransport) Start(_ context.Context) error       { return nil }
func (m *mockTransport) Stop() error                          { return nil }
func (m *mockTransport) IsConnected() bool                    { return m.connected }
func (m *mockTransport) SetPacketHandler(fn transport.PacketHandler) { m.handler = fn }
func (m *mockTransport) SetStateHandler(_ transport.StateHandler)    {}
func (m *mockTransport) AddChannel(_ string)                         {}
func (m *mockTransport) SendPacket(channel string, pkt *pb.MeshPacket) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentPacket{channel: channel, packet: pkt})
	return nil
}

func (m *mockTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *mockTransport) lastSent() sentPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent[len(m.sent)-1]
}

func defaultChannels() *pb.ChannelSet {
	return &pb.ChannelSet{
		Settings: []*pb.ChannelSettings{
			{Name: "LongFast", Psk: crypto.DefaultKey},
		},
	}
}

func newTestNode(t *testing.T, mt *mockTransport, opts ...func(*Config)) *Node {
	t.Helper()
	cfg := Config{
		Transport: mt,
		NodeID:    core.NodeID(0x12345678),
		Channels:  defaultChannels(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return n
}

// inject simulates an incoming packet from the transport.
func inject(n *Node, mt *mockTransport, pkt transport.NetworkPacket) {
	if mt.handler != nil {
		mt.handler(pkt)
	} else {
		n.handleIncomingPacket(pkt)
	}
}

func TestDedup_DuplicateDropped(t *testing.T) {
	mt := newMockTransport()
	var received int
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(_ any) { received++ }}
	})

	user := &pb.User{LongName: "Test"}
	userBytes, _ := proto.Marshal(user)
	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   42,
			From: 0xAA,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_NODEINFO_APP,
					Payload: userBytes,
				},
			},
		},
		Channel: "LongFast",
	}

	inject(n, mt, pkt)
	inject(n, mt, pkt) // duplicate

	if received != 1 {
		t.Errorf("expected 1 event, got %d", received)
	}
}

func TestDedup_ZeroIDNotDeduped(t *testing.T) {
	mt := newMockTransport()
	var received int
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(_ any) { received++ }}
	})

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   0, // zero ID should not be deduped
			From: 0xAA,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_TEXT_MESSAGE_APP,
					Payload: []byte("hello"),
				},
			},
		},
	}

	inject(n, mt, pkt)
	inject(n, mt, pkt)

	if received != 2 {
		t.Errorf("expected 2 events for zero-ID packets, got %d", received)
	}
}

func TestMultiChannel_PSKDecrypt(t *testing.T) {
	mt := newMockTransport()
	var received []string
	secondKey := make([]byte, 16)
	copy(secondKey, crypto.DefaultKey)
	secondKey[15] = 0x42

	n := newTestNode(t, mt, func(c *Config) {
		c.Channels = &pb.ChannelSet{
			Settings: []*pb.ChannelSettings{
				{Name: "LongFast", Psk: crypto.DefaultKey},
				{Name: "SecondCh", Psk: secondKey},
			},
		}
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.TextMessage); ok {
				received = append(received, e.ChannelName)
			}
		}}
	})

	// Encrypt a text message on the second channel
	data := &pb.Data{
		Portnum: pb.PortNum_TEXT_MESSAGE_APP,
		Payload: []byte("hello on second channel"),
	}
	dataBytes, _ := proto.Marshal(data)

	hash, _ := crypto.ChannelHash("SecondCh", secondKey)
	encrypted, _ := crypto.XOR(dataBytes, secondKey, 99, 0xBB)

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:      99,
			From:    0xBB,
			To:      core.BroadcastNodeID.Uint32(),
			Channel: hash,
			PayloadVariant: &pb.MeshPacket_Encrypted{
				Encrypted: encrypted,
			},
		},
		Channel: "SecondCh",
	}

	inject(n, mt, pkt)

	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	if received[0] != "SecondCh" {
		t.Errorf("expected channel %q, got %q", "SecondCh", received[0])
	}
}

func TestEvents_TextMessage(t *testing.T) {
	mt := newMockTransport()
	var got *event.TextMessage
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.TextMessage); ok {
				got = e
			}
		}}
	})

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   1,
			From: 0xAA,
			To:   core.BroadcastNodeID.Uint32(),
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_TEXT_MESSAGE_APP,
					Payload: []byte("hello world"),
					ReplyId: 5,
					Emoji:   0,
				},
			},
		},
	}

	inject(n, mt, pkt)

	if got == nil {
		t.Fatal("expected TextMessage event")
	}
	if got.Message != "hello world" {
		t.Errorf("got message %q, want %q", got.Message, "hello world")
	}
	if got.IsDM {
		t.Error("expected IsDM=false for broadcast")
	}
	if got.ReplyID != 5 {
		t.Errorf("got ReplyID %d, want 5", got.ReplyID)
	}
	if got.From != core.NodeID(0xAA) {
		t.Errorf("got From %s, want !000000aa", got.From)
	}
}

func TestEvents_TextMessageDM(t *testing.T) {
	mt := newMockTransport()
	var got *event.TextMessage
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.TextMessage); ok {
				got = e
			}
		}}
	})

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   2,
			From: 0xAA,
			To:   0x12345678, // unicast to our node
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_TEXT_MESSAGE_APP,
					Payload: []byte("DM"),
				},
			},
		},
	}

	inject(n, mt, pkt)

	if got == nil {
		t.Fatal("expected TextMessage event")
	}
	if !got.IsDM {
		t.Error("expected IsDM=true for unicast message")
	}
}

func TestEvents_NodeInfoUpdatesDB(t *testing.T) {
	mt := newMockTransport()
	var got *event.NodeInfoUpdated
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.NodeInfoUpdated); ok {
				got = e
			}
		}}
	})

	user := &pb.User{LongName: "TestUser", ShortName: "TU"}
	userBytes, _ := proto.Marshal(user)

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   10,
			From: 0xCC,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_NODEINFO_APP,
					Payload: userBytes,
				},
			},
		},
	}

	inject(n, mt, pkt)

	// Verify event
	if got == nil {
		t.Fatal("expected NodeInfoUpdated event")
	}
	if got.User.LongName != "TestUser" {
		t.Errorf("event user LongName = %q, want %q", got.User.LongName, "TestUser")
	}

	// Verify nodedb was updated
	dbNode := n.NodeDB().Get(0xCC)
	if dbNode == nil {
		t.Fatal("expected node in DB")
	}
	if dbNode.User.LongName != "TestUser" {
		t.Errorf("DB user LongName = %q, want %q", dbNode.User.LongName, "TestUser")
	}
}

func TestEvents_PacketReceivedForUnknownPortnum(t *testing.T) {
	mt := newMockTransport()
	var got *event.PacketReceived
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.PacketReceived); ok {
				got = e
			}
		}}
	})

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   20,
			From: 0xDD,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_WAYPOINT_APP,
					Payload: []byte("waypoint data"),
				},
			},
		},
	}

	inject(n, mt, pkt)

	if got == nil {
		t.Fatal("expected PacketReceived event for unknown portnum")
	}
	if got.Portnum != pb.PortNum_WAYPOINT_APP {
		t.Errorf("got portnum %v, want WAYPOINT_APP", got.Portnum)
	}
}

func TestOnEvent_ThreadSafe(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)

	var count int
	var mu sync.Mutex

	// Register handlers concurrently
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.OnEvent(func(_ any) {
				mu.Lock()
				count++
				mu.Unlock()
			})
		}()
	}
	wg.Wait()

	// Send a packet
	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:   30,
			From: 0xEE,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_TEXT_MESSAGE_APP,
					Payload: []byte("test"),
				},
			},
		},
	}
	inject(n, mt, pkt)

	mu.Lock()
	if count != 10 {
		t.Errorf("expected 10 handler calls, got %d", count)
	}
	mu.Unlock()
}

func TestSendPacket_DefaultsToPrimary(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)

	err := n.sendPacket(context.Background(), &pb.MeshPacket{
		From: 0x12345678,
		To:   core.BroadcastNodeID.Uint32(),
	}, "")
	if err != nil {
		t.Fatalf("sendPacket error: %v", err)
	}

	sent := mt.lastSent()
	if sent.channel != "LongFast" {
		t.Errorf("expected channel %q, got %q", "LongFast", sent.channel)
	}
	if sent.packet.Id == 0 {
		t.Error("expected non-zero packet ID")
	}
}

func TestSendPacket_SpecificChannel(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt)

	err := n.sendPacket(context.Background(), &pb.MeshPacket{
		From: 0x12345678,
	}, "CustomChannel")
	if err != nil {
		t.Fatalf("sendPacket error: %v", err)
	}

	if mt.lastSent().channel != "CustomChannel" {
		t.Errorf("expected channel %q, got %q", "CustomChannel", mt.lastSent().channel)
	}
}

func TestPKI_DisabledByDefault(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt) // no PKI keys

	pkt := &pb.MeshPacket{
		Channel: 0,
		To:      0x12345678,
		From:    0xAA,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: []byte("fake encrypted data"),
		},
	}

	if n.shouldTryPKI(pkt) {
		t.Error("shouldTryPKI should return false when PKI keys are nil")
	}
}

func TestPKI_ShouldTryPKI(t *testing.T) {
	mt := newMockTransport()
	n := newTestNode(t, mt, func(c *Config) {
		c.PrivateKey = make([]byte, 32)
		c.PublicKey = make([]byte, 32)
	})

	tests := []struct {
		name   string
		pkt    *pb.MeshPacket
		expect bool
	}{
		{
			name: "PKI candidate",
			pkt: &pb.MeshPacket{
				Channel: 0, To: 0x12345678, From: 0xAA,
				PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: []byte("data")},
			},
			expect: true,
		},
		{
			name: "non-zero channel",
			pkt: &pb.MeshPacket{
				Channel: 5, To: 0x12345678, From: 0xAA,
				PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: []byte("data")},
			},
			expect: false,
		},
		{
			name: "broadcast destination",
			pkt: &pb.MeshPacket{
				Channel: 0, To: core.BroadcastNodeID.Uint32(), From: 0xAA,
				PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: []byte("data")},
			},
			expect: false,
		},
		{
			name: "unmanaged destination",
			pkt: &pb.MeshPacket{
				Channel: 0, To: 0x99999999, From: 0xAA,
				PayloadVariant: &pb.MeshPacket_Encrypted{Encrypted: []byte("data")},
			},
			expect: false,
		},
		{
			name: "decoded packet (not encrypted)",
			pkt: &pb.MeshPacket{
				Channel: 0, To: 0x12345678, From: 0xAA,
				PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{}},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := n.shouldTryPKI(tt.pkt); got != tt.expect {
				t.Errorf("shouldTryPKI() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestPKI_RoundTrip(t *testing.T) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	senderPub, senderPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	mt := newMockTransport()
	var got *event.TextMessage
	n := newTestNode(t, mt, func(c *Config) {
		c.PrivateKey = priv
		c.PublicKey = pub
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.TextMessage); ok {
				got = e
			}
		}}
	})

	// Seed sender's public key in NodeDB so PKI decryption can look it up
	n.db.Update(0xAA, func(info *pb.NodeInfo) {
		info.User = &pb.User{PublicKey: senderPub}
	})

	// Encrypt a text message using PKI (sender's private key + recipient's public key)
	data := &pb.Data{
		Portnum: pb.PortNum_TEXT_MESSAGE_APP,
		Payload: []byte("secret DM"),
	}
	dataBytes, _ := proto.Marshal(data)

	packetID := uint32(123)
	encrypted, err := crypto.EncryptCurve25519(dataBytes, senderPriv, pub, packetID, 0xAA)
	if err != nil {
		t.Fatalf("EncryptCurve25519: %v", err)
	}

	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:      packetID,
			From:    0xAA,
			To:      0x12345678,
			Channel: 0,
			PayloadVariant: &pb.MeshPacket_Encrypted{
				Encrypted: encrypted,
			},
		},
	}

	inject(n, mt, pkt)

	if got == nil {
		t.Fatal("expected TextMessage event from PKI-decrypted packet")
	}
	if got.Message != "secret DM" {
		t.Errorf("got message %q, want %q", got.Message, "secret DM")
	}
	if !got.IsPKI {
		t.Error("expected IsPKI=true")
	}
	if !got.IsDM {
		t.Error("expected IsDM=true")
	}
	if got.ChannelName != "PKI" {
		t.Errorf("got channel %q, want %q", got.ChannelName, "PKI")
	}
}

func TestSendData_PKI(t *testing.T) {
	_, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	recipientPub, _, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	mt := newMockTransport()
	n := newTestNode(t, mt, func(c *Config) {
		c.PrivateKey = priv
		c.PublicKey = make([]byte, 32) // own public key (not needed for send)
	})

	// Seed recipient's public key in NodeDB
	n.db.Update(0xBB, func(info *pb.NodeInfo) {
		info.User = &pb.User{PublicKey: recipientPub}
	})

	data := &pb.Data{
		Portnum: pb.PortNum_TEXT_MESSAGE_APP,
		Payload: []byte("outgoing PKI"),
	}
	err = n.SendData(context.Background(), core.NodeID(0xBB), data, true)
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 sent packet, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.packet.Channel != 0 {
		t.Errorf("PKI packet should have Channel=0, got %d", sent.packet.Channel)
	}
	if !sent.packet.PkiEncrypted {
		t.Error("expected PkiEncrypted=true")
	}
	if sent.packet.From != 0x12345678 {
		t.Errorf("expected From=0x12345678, got %x", sent.packet.From)
	}
	if sent.packet.To != 0xBB {
		t.Errorf("expected To=0xBB, got %x", sent.packet.To)
	}
	if sent.channel != "LongFast" {
		t.Errorf("expected transport channel %q, got %q", "LongFast", sent.channel)
	}
}

func TestEventTimestamp_UsesRxTime(t *testing.T) {
	mt := newMockTransport()
	var got *event.TextMessage
	n := newTestNode(t, mt, func(c *Config) {
		c.EventHandlers = []event.Handler{func(evt any) {
			if e, ok := evt.(*event.TextMessage); ok {
				got = e
			}
		}}
	})

	rxTime := uint32(1700000000)
	pkt := transport.NetworkPacket{
		Packet: &pb.MeshPacket{
			Id:     50,
			From:   0xAA,
			RxTime: rxTime,
			PayloadVariant: &pb.MeshPacket_Decoded{
				Decoded: &pb.Data{
					Portnum: pb.PortNum_TEXT_MESSAGE_APP,
					Payload: []byte("timed"),
				},
			},
		},
	}

	inject(n, mt, pkt)

	if got == nil {
		t.Fatal("expected event")
	}
	expected := time.Unix(int64(rxTime), 0)
	if !got.Timestamp.Equal(expected) {
		t.Errorf("got timestamp %v, want %v", got.Timestamp, expected)
	}
}
