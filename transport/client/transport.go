// Package client provides client transport implementations for connecting to Meshtastic devices.
package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrTimeout is returned when the connection times out.
	ErrTimeout = errors.New("timeout connecting to radio")
	// ErrNotConnected is returned when attempting to send without being connected.
	ErrNotConnected = errors.New("not connected")
)

// heartbeatInterval keeps the device from dropping us as idle. Firmware closes an
// API client after 15 minutes without any ToRadio.
const heartbeatInterval = 5 * time.Minute

// ClientTransport extends the base Transport interface with client-specific functionality.
type ClientTransport interface {
	transport.Transport
	// Connect performs the handshake with the device and populates state.
	Connect(ctx context.Context) error
	// SendToRadio sends a ToRadio message to the connected device.
	SendToRadio(msg *pb.ToRadio) error
	// State returns the device state populated during handshake.
	State() *DeviceState
	// Handle registers a handler for a specific message type.
	// Returns a Subscription that can be used to unsubscribe.
	Handle(kind proto.Message, handler MessageHandler) *Subscription
}

// Transport is a client transport that connects to a Meshtastic device over a stream connection.
type Transport struct {
	mu           sync.RWMutex
	conn         *stream.Conn
	handlers     *HandlerRegistry
	log          *slog.Logger
	state        DeviceState
	connected    bool
	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler

	heartbeatInterval time.Duration
	done              chan struct{}
	closeDone         sync.Once
}

// TransportConfig configures a client transport.
type TransportConfig struct {
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
	// ErrorOnNoHandler determines if HandleMessage returns an error when no handlers are registered.
	ErrorOnNoHandler bool
}

// NewTransport creates a new client transport from a stream connection.
func NewTransport(conn *stream.Conn, cfg TransportConfig) *Transport {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Transport{
		conn:              conn,
		handlers:          NewHandlerRegistry(cfg.ErrorOnNoHandler),
		log:               logger.WithGroup("client"),
		heartbeatInterval: heartbeatInterval,
		done:              make(chan struct{}),
	}
}

// State returns the device state.
func (t *Transport) State() *DeviceState {
	return &t.state
}

// Handle registers a handler for a specific message type.
func (t *Transport) Handle(kind proto.Message, handler MessageHandler) *Subscription {
	return t.handlers.Register(kind, handler)
}

// SendToRadio sends a ToRadio message to the device.
func (t *Transport) SendToRadio(msg *pb.ToRadio) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.connected {
		return ErrNotConnected
	}
	return t.conn.Write(msg)
}

// Start implements transport.Transport.
func (t *Transport) Start(ctx context.Context) error {
	return t.Connect(ctx)
}

// Stop implements transport.Transport.
func (t *Transport) Stop() error {
	t.stopHeartbeat()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = false
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// IsConnected implements transport.Transport.
func (t *Transport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected
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

// Connect performs the handshake with the device.
func (t *Transport) Connect(ctx context.Context) error {
	if err := t.sendGetConfig(); err != nil {
		return fmt.Errorf("requesting config: %w", err)
	}

	cfgComplete := make(chan struct{})
	go t.readLoop(cfgComplete)

	select {
	case <-ctx.Done():
		return ErrTimeout
	case <-cfgComplete:
		t.mu.Lock()
		t.connected = true
		t.mu.Unlock()
		if t.stateHandler != nil {
			t.stateHandler(t, transport.ListenerEventConnected)
		}
		go t.heartbeatLoop()
		return nil
	}
}

func (t *Transport) heartbeatLoop() {
	ticker := time.NewTicker(t.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			msg := &pb.ToRadio{PayloadVariant: &pb.ToRadio_Heartbeat{Heartbeat: &pb.Heartbeat{}}}
			if err := t.conn.Write(msg); err != nil {
				t.log.Warn("sending heartbeat", "err", err)
			}
		}
	}
}

func (t *Transport) stopHeartbeat() {
	t.closeDone.Do(func() { close(t.done) })
}

func (t *Transport) sendGetConfig() error {
	r := rand.Uint32()
	t.state.SetConfigID(r)
	msg := &pb.ToRadio{
		PayloadVariant: &pb.ToRadio_WantConfigId{
			WantConfigId: r,
		},
	}
	t.log.Debug("sending want config", "id", r)
	if err := t.conn.Write(msg); err != nil {
		return fmt.Errorf("writing want config command: %w", err)
	}
	t.log.Debug("sent want config")
	return nil
}

func (t *Transport) readLoop(cfgComplete chan struct{}) {
	defer t.stopHeartbeat()
	signaled := false
	for {
		msg := &pb.FromRadio{}
		err := t.conn.Read(msg)
		if err != nil {
			t.log.Error("error reading from radio", "err", err)
			if t.stateHandler != nil {
				t.stateHandler(t, transport.ListenerEventDisconnected)
			}
			return
		}
		t.log.Debug("received message from radio", "msg", msg)

		var variant proto.Message
		switch payload := msg.GetPayloadVariant().(type) {
		// These protobufs all get sent upon initial connection to the node
		case *pb.FromRadio_MyInfo:
			t.state.SetNodeInfo(msg.GetMyInfo())
			variant = msg.GetMyInfo()
		case *pb.FromRadio_Metadata:
			t.state.SetDeviceMetadata(msg.GetMetadata())
			variant = msg.GetMetadata()
		case *pb.FromRadio_NodeInfo:
			node := msg.GetNodeInfo()
			t.state.AddNode(node)
			variant = node
		case *pb.FromRadio_Channel:
			channel := msg.GetChannel()
			t.state.AddChannel(channel)
			variant = channel
		case *pb.FromRadio_Config:
			cfg := msg.GetConfig()
			t.state.AddConfig(cfg)
			variant = cfg
		case *pb.FromRadio_ModuleConfig:
			cfg := msg.GetModuleConfig()
			t.state.AddModule(cfg)
			variant = cfg
		case *pb.FromRadio_ConfigCompleteId:
			t.log.Debug("config complete")
			t.state.SetComplete(true)
			if !signaled {
				signaled = true
				close(cfgComplete)
			}
			continue

		// Below are packets not part of initial connection
		case *pb.FromRadio_LogRecord:
			variant = msg.GetLogRecord()
		case *pb.FromRadio_MqttClientProxyMessage:
			variant = msg.GetMqttClientProxyMessage()
		case *pb.FromRadio_QueueStatus:
			variant = msg.GetQueueStatus()
		case *pb.FromRadio_Rebooted:
			// A rebooted device sends nothing until asked for its config again. Over
			// USB the port usually drops instead, but a UART bridge stays open.
			if t.state.Complete() {
				t.log.Info("device rebooted, requesting config again")
				t.state.Reset()
				if err := t.sendGetConfig(); err != nil {
					t.log.Error("requesting config after reboot", "err", err)
				}
			}
			continue
		case *pb.FromRadio_XmodemPacket:
			variant = msg.GetXmodemPacket()
		case *pb.FromRadio_Packet:
			variant = msg.GetPacket()
			// Also dispatch to packet handler
			if t.packetHandler != nil && payload.Packet != nil {
				t.packetHandler(transport.NetworkPacket{
					Packet:  payload.Packet,
					Source:  transport.PacketSourceRadio,
				})
			}
		default:
			// Newer variants (client notifications, file info, region presets, and
			// whatever comes next) carry no handshake state, so just dispatch them.
			variant = oneofMessage(msg)
			if variant == nil {
				t.log.Warn("unhandled protobuf from radio")
				continue
			}
		}

		if !t.state.Complete() {
			continue
		}

		if variant != nil {
			if err := t.handlers.HandleMessage(variant); err != nil {
				t.log.Error("error handling message", "err", err)
			}
		}
	}
}

// oneofMessage returns the message a FromRadio carries, or nil for a scalar or
// unknown variant.
func oneofMessage(msg *pb.FromRadio) proto.Message {
	m := msg.ProtoReflect()
	fd := m.WhichOneof(m.Descriptor().Oneofs().ByName("payload_variant"))
	if fd == nil || fd.Message() == nil {
		return nil
	}
	return m.Get(fd).Message().Interface()
}
