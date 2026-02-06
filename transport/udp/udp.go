// Package udp provides a UDP multicast transport for receiving Meshtastic mesh packets.
// This transport works with Meshtastic firmware 2.6+ which broadcasts mesh packets via UDP multicast.
package udp

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

const (
	// MulticastIP is the multicast group address used by Meshtastic devices.
	MulticastIP = "224.0.0.69"
	// MulticastPort is the port used by Meshtastic devices for UDP multicast.
	MulticastPort = 4403

	maxReconnectDelay = 30 * time.Second
	bufferSize        = 2048
)

// Config holds the configuration for a UDP transport.
type Config struct {
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Transport implements a raw transport over UDP multicast.
type Transport struct {
	conn         *net.UDPConn
	log          *slog.Logger
	running      atomic.Bool
	listening    atomic.Bool
	stopChan     chan struct{}
	waitGroup    sync.WaitGroup
	reconnectMux sync.Mutex
	isRestart    bool

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
	return &Transport{
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
	t.waitGroup.Wait()
	t.closeConn()
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

	dst := &net.UDPAddr{
		IP:   net.ParseIP(MulticastIP),
		Port: MulticastPort,
	}

	conn, err := net.DialUDP("udp", nil, dst)
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
			time.Sleep(delay)
			delay = minDuration(delay*2, maxReconnectDelay)
			continue
		}

		t.listening.Store(true)

		if t.isRestart {
			t.emitStateEvent(transport.ListenerEventReconnecting)
		} else {
			t.emitStateEvent(transport.ListenerEventConnected)
		}

		t.isRestart = true
		t.log.Info("listening for UDP multicast", "addr", t.conn.LocalAddr().String())

		if t.listenLoop() == nil {
			break // graceful shutdown
		}

		t.log.Warn("UDP listener restarting", "retry_in", delay)
		t.closeConn()
		t.listening.Store(false)
		t.emitStateEvent(transport.ListenerEventDisconnected)
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
				t.log.Error("read error", "error", err)
				return err
			}

			msg := &pb.MeshPacket{}
			if err := proto.Unmarshal(buf[:n], msg); err != nil {
				t.log.Warn("unmarshal error", "error", err)
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

func (t *Transport) setupSocket() error {
	t.reconnectMux.Lock()
	defer t.reconnectMux.Unlock()

	group := &net.UDPAddr{
		IP:   net.ParseIP(MulticastIP),
		Port: MulticastPort,
	}

	conn, err := net.ListenMulticastUDP("udp", nil, group)
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
