package raw

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core/dedupe"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
)

// MultiConfig holds configuration for a MultiTransport.
type MultiConfig struct {
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// TransportOption configures a child transport within a MultiTransport.
type TransportOption struct {
	// Transport is the raw transport to multiplex.
	Transport RawTransport
	// SendDelay is the delay before each send on this transport.
	// Used to deprioritize slower transports (e.g., 700ms for MQTT).
	SendDelay time.Duration
	// RecvDelay is the delay before dispatching received packets from this transport.
	// Used to let faster transports deliver first (e.g., 500ms for MQTT).
	RecvDelay time.Duration
}

type multiEntry struct {
	transport RawTransport
	sendDelay time.Duration
	recvDelay time.Duration
}

// MultiTransport multiplexes multiple raw transports into a single
// RawTransport interface. Outbound packets are sent to all connected
// transports in parallel. Inbound packets are deduplicated across
// transports so each packet is delivered exactly once.
type MultiTransport struct {
	transports []multiEntry
	dedup      *dedupe.PacketDeduplicator
	log        *slog.Logger

	mu      sync.RWMutex
	handler transport.PacketHandler
	state   transport.StateHandler
}

// NewMultiTransport creates a MultiTransport that multiplexes the given
// transports. At least one transport must be provided.
func NewMultiTransport(cfg MultiConfig, transports ...TransportOption) *MultiTransport {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	entries := make([]multiEntry, len(transports))
	for i, t := range transports {
		entries[i] = multiEntry{
			transport: t.Transport,
			sendDelay: t.SendDelay,
			recvDelay: t.RecvDelay,
		}
	}

	return &MultiTransport{
		transports: entries,
		dedup:      dedupe.NewDeduplicator(30 * time.Second),
		log:        logger.WithGroup("multi"),
	}
}

// Start starts all child transports. Succeeds if at least one transport
// starts successfully. Failed transports are logged as warnings.
func (m *MultiTransport) Start(ctx context.Context) error {
	var errs []error
	started := 0
	for _, e := range m.transports {
		if err := e.transport.Start(ctx); err != nil {
			m.log.Warn("transport failed to start", "error", err)
			errs = append(errs, err)
		} else {
			started++
		}
	}
	if started == 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Stop stops all child transports.
func (m *MultiTransport) Stop() error {
	var errs []error
	for _, e := range m.transports {
		if err := e.transport.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// IsConnected returns true if any child transport is connected.
func (m *MultiTransport) IsConnected() bool {
	for _, e := range m.transports {
		if e.transport.IsConnected() {
			return true
		}
	}
	return false
}

// SetPacketHandler installs the packet handler. An internal deduplicating
// handler is installed on each child transport that applies recv delays
// and filters duplicate packets before forwarding to the user's handler.
func (m *MultiTransport) SetPacketHandler(fn transport.PacketHandler) {
	m.mu.Lock()
	m.handler = fn
	m.mu.Unlock()

	for i := range m.transports {
		e := &m.transports[i]
		e.transport.SetPacketHandler(m.makeChildHandler(e))
	}
}

// SetStateHandler installs the state handler. State events are aggregated:
// Connected is emitted when the first transport connects, Disconnected only
// when all transports are disconnected.
func (m *MultiTransport) SetStateHandler(fn transport.StateHandler) {
	m.mu.Lock()
	m.state = fn
	m.mu.Unlock()

	for i := range m.transports {
		e := &m.transports[i]
		e.transport.SetStateHandler(m.makeChildStateHandler(e))
	}
}

// AddChannel subscribes all child transports to a channel.
func (m *MultiTransport) AddChannel(channelName string) {
	for _, e := range m.transports {
		e.transport.AddChannel(channelName)
	}
}

// SendPacket sends a packet via all connected child transports in parallel.
// Each transport's send delay is applied before sending. Returns an error
// only if all transports fail.
func (m *MultiTransport) SendPacket(channel string, packet *pb.MeshPacket) error {
	connected := make([]multiEntry, 0, len(m.transports))
	for _, e := range m.transports {
		if e.transport.IsConnected() {
			connected = append(connected, e)
		}
	}
	if len(connected) == 0 {
		return errors.New("no transports connected")
	}

	errs := make([]error, len(connected))
	var wg sync.WaitGroup
	wg.Add(len(connected))

	for i, e := range connected {
		go func(idx int, entry multiEntry) {
			defer wg.Done()
			if entry.sendDelay > 0 {
				time.Sleep(entry.sendDelay)
			}
			errs[idx] = entry.transport.SendPacket(channel, packet)
		}(i, e)
	}
	wg.Wait()

	// Succeed if any transport succeeded.
	var failures []error
	for _, err := range errs {
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == len(connected) {
		return errors.Join(failures...)
	}
	return nil
}

func (m *MultiTransport) makeChildHandler(e *multiEntry) transport.PacketHandler {
	return func(pkt transport.NetworkPacket) {
		if e.recvDelay > 0 {
			time.Sleep(e.recvDelay)
		}

		// Deduplicate across transports. Packets with Id=0 bypass dedup
		// (matching firmware behavior).
		if pkt.Packet != nil && pkt.Packet.Id != 0 {
			if m.dedup.Seen(pkt.Packet.From, pkt.Packet.Id) {
				return
			}
		}

		m.mu.RLock()
		handler := m.handler
		m.mu.RUnlock()

		if handler != nil {
			handler(pkt)
		}
	}
}

func (m *MultiTransport) makeChildStateHandler(e *multiEntry) transport.StateHandler {
	return func(_ transport.Transport, event transport.ListenerEvent) {
		m.mu.RLock()
		handler := m.state
		m.mu.RUnlock()

		if handler == nil {
			return
		}

		switch event {
		case transport.ListenerEventDisconnected:
			// Only emit disconnected if ALL transports are down.
			for _, other := range m.transports {
				if other.transport.IsConnected() {
					return
				}
			}
			handler(m, transport.ListenerEventDisconnected)

		case transport.ListenerEventConnected:
			// Emit connected — the multi-transport is now usable.
			handler(m, transport.ListenerEventConnected)

		case transport.ListenerEventReconnecting:
			// Only emit reconnecting if no other transport is connected.
			for _, other := range m.transports {
				if &other != e && other.transport.IsConnected() {
					return
				}
			}
			handler(m, transport.ListenerEventReconnecting)

		default:
			handler(m, event)
		}
	}
}
