// Package udp provides a UDP multicast transport for receiving Meshtastic mesh packets.
// This transport works with Meshtastic firmware 2.6+ which broadcasts mesh packets via UDP multicast.
package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

const (
	// MulticastIP is the multicast group firmware 2.8 and later uses. It sits in the
	// administratively scoped range, which some access points require.
	MulticastIP = "239.0.0.69"
	// LegacyMulticastIP is the group firmware 2.6 and 2.7 used. Upstream moved off it
	// without a transition period, so a mixed network needs one transport per group.
	LegacyMulticastIP = "224.0.0.69"
	// MulticastPort is the port used by Meshtastic devices for UDP multicast.
	MulticastPort = 4403

	maxReconnectDelay = 30 * time.Second
	bufferSize        = 2048
)

// Config holds the configuration for a UDP transport.
type Config struct {
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
	// MulticastIP is the multicast group to join and send to. Defaults to
	// MulticastIP; set LegacyMulticastIP to talk to pre-2.8 firmware.
	MulticastIP string
}

// Transport implements a raw transport over UDP multicast.
type Transport struct {
	conn         *net.UDPConn
	group        *net.UDPAddr
	log          *slog.Logger
	running      atomic.Bool
	listening    atomic.Bool
	stopChan     chan struct{}
	waitGroup    sync.WaitGroup
	reconnectMux sync.Mutex

	mu            sync.RWMutex
	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler
}

// New creates a new UDP transport.
func New(cfg Config) *Transport {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ip := cfg.MulticastIP
	if ip == "" {
		ip = MulticastIP
	}
	return &Transport{
		group:    &net.UDPAddr{IP: net.ParseIP(ip), Port: MulticastPort},
		log:      logger.WithGroup("udp"),
		stopChan: make(chan struct{}),
	}
}

// Start implements transport.Transport.
func (t *Transport) Start(_ context.Context) error {
	if t.running.Load() {
		return nil
	}
	t.running.Store(true)
	t.stopChan = make(chan struct{})

	t.waitGroup.Add(1)
	go t.listenWithReconnect()
	return nil
}

// Stop implements transport.Transport.
func (t *Transport) Stop() error {
	if !t.running.Load() {
		return nil
	}
	t.running.Store(false)
	t.listening.Store(false)
	close(t.stopChan)
	// Close before waiting: the read loop only notices stopChan between reads, so
	// an idle socket would otherwise block shutdown until a packet arrives.
	t.closeConn()
	t.waitGroup.Wait()
	return nil
}

// IsConnected implements transport.Transport.
func (t *Transport) IsConnected() bool {
	return t.listening.Load()
}

// SetPacketHandler implements transport.Transport.
func (t *Transport) SetPacketHandler(fn transport.PacketHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.packetHandler = fn
}

// SetStateHandler implements transport.Transport.
func (t *Transport) SetStateHandler(fn transport.StateHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stateHandler = fn
}

// AddChannel is a no-op for UDP transport as it receives all packets on the network.
func (t *Transport) AddChannel(_ string) {
	// No-op: UDP receives all packets regardless of channel
}

// SendPacket sends a mesh packet via UDP multicast.
func (t *Transport) SendPacket(_ string, packet *pb.MeshPacket) error {
	data, err := proto.Marshal(packet)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, t.group)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	return err
}

func (t *Transport) listenWithReconnect() {
	defer t.waitGroup.Done()
	delay := 1 * time.Second

	for t.running.Load() {
		err := t.setupSocket()
		if err != nil {
			t.log.Warn("UDP setup failed", "error", err)
			t.listening.Store(false)
			t.emitStateEvent(transport.ListenerEventError)
			t.emitStateEvent(transport.ListenerEventReconnecting)
			time.Sleep(delay)
			delay = minDuration(delay*2, maxReconnectDelay)
			continue
		}

		t.listening.Store(true)
		delay = 1 * time.Second

		// Connected fires on every successful bind, not only the first. Reconnecting
		// means a retry is pending, matching the MQTT transport, so consumers that
		// cancelled work on Disconnected know to resume here.
		t.emitStateEvent(transport.ListenerEventConnected)
		t.log.Info("listening for UDP multicast", "addr", t.conn.LocalAddr().String())

		if t.listenLoop() == nil {
			break // graceful shutdown
		}

		t.log.Warn("UDP listener restarting", "retry_in", delay)
		t.closeConn()
		t.listening.Store(false)
		t.emitStateEvent(transport.ListenerEventDisconnected)
		t.emitStateEvent(transport.ListenerEventReconnecting)
		time.Sleep(delay)
		delay = minDuration(delay*2, maxReconnectDelay)
	}

	t.listening.Store(false)
}

func (t *Transport) listenLoop() error {
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-t.stopChan:
			return nil
		default:
			n, _, err := t.conn.ReadFromUDP(buf)
			if err != nil {
				if !t.running.Load() {
					return nil
				}
				t.log.Error("read error", "error", err)
				return err
			}

			msg := &pb.MeshPacket{}
			if err := proto.Unmarshal(buf[:n], msg); err != nil {
				t.log.Warn("unmarshal error", "error", err)
				continue
			}
			if err := sanitizeInbound(msg); err != nil {
				t.log.Debug("dropping UDP packet", "from", msg.From, "reason", err)
				continue
			}

			t.mu.RLock()
			handler := t.packetHandler
			t.mu.RUnlock()

			if handler != nil {
				handler(transport.NetworkPacket{
					Packet: msg,
					Source: transport.PacketSourceUDP,
				})
			}
		}
	}
}

// sanitizeInbound applies the gates firmware runs on a LAN packet before it reaches
// the router. UDP carries no authenticity of its own, so anything a peer could set to
// look trusted is cleared, and anything that can only be a forgery is dropped. The one
// firmware check missing here is from == self, which needs an identity the transport
// doesn't have; the node pipelines apply it.
func sanitizeInbound(msg *pb.MeshPacket) error {
	if _, ok := msg.GetPayloadVariant().(*pb.MeshPacket_Encrypted); !ok {
		return errors.New("payload is not encrypted")
	}
	if msg.From == 0 {
		return errors.New("from is zero")
	}
	if msg.HopLimit > core.MaxHops || msg.HopStart > core.MaxHops {
		return fmt.Errorf("hop_limit %d or hop_start %d exceeds %d", msg.HopLimit, msg.HopStart, core.MaxHops)
	}

	msg.TransportMechanism = pb.MeshPacket_TRANSPORT_MULTICAST_UDP
	// Only our own decryption may establish these.
	msg.PkiEncrypted = false
	msg.PublicKey = nil
	// No local RF measurement exists for a UDP arrival. Whatever values came in belong
	// to the node that put the packet on the wire, so clear presence, not just the number.
	msg.RxSnr = 0
	msg.RxRssi = nil
	return nil
}

func (t *Transport) setupSocket() error {
	t.reconnectMux.Lock()
	defer t.reconnectMux.Unlock()

	conn, err := net.ListenMulticastUDP("udp", nil, t.group)
	if err != nil {
		return err
	}
	if err := conn.SetReadBuffer(bufferSize); err != nil {
		t.log.Warn("SetReadBuffer failed", "error", err)
	}
	t.conn = conn
	return nil
}

func (t *Transport) closeConn() {
	t.reconnectMux.Lock()
	defer t.reconnectMux.Unlock()
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
}

func (t *Transport) emitStateEvent(event transport.ListenerEvent) {
	t.mu.RLock()
	handler := t.stateHandler
	t.mu.RUnlock()

	if handler != nil {
		handler(t, event)
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
