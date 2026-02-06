// Package mqtt provides an MQTT transport for connecting to Meshtastic mesh networks.
package mqtt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/generated"
	"github.com/kabili207/meshtastic-go/transport"
	"google.golang.org/protobuf/proto"
)

const (
	// ProtoTopic is the topic suffix for protobuf mesh packets.
	ProtoTopic = "/2/e/"
	// MapTopic is the topic suffix for map reports.
	MapTopic = "/2/map/"
	// PKITopic is the topic suffix for PKI-encrypted packets.
	PKITopic = ProtoTopic + "PKI/"
)

// Default MQTT broker settings.
const (
	DefaultBroker   = "tcp://mqtt.meshtastic.org:1883"
	DefaultUsername = "meshdev"
	DefaultPassword = "large4cats"
	DefaultRoot     = "msh/US"
)

// Config holds the configuration for an MQTT transport.
type Config struct {
	// Broker is the MQTT broker URL (e.g., "tcp://mqtt.meshtastic.org:1883").
	Broker string
	// Username for MQTT authentication.
	Username string
	// Password for MQTT authentication.
	Password string
	// Root is the topic root (e.g., "msh/US").
	Root string
	// NodeID is this virtual node's ID.
	NodeID core.NodeID
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Transport implements a raw transport over MQTT.
type Transport struct {
	cfg           Config
	client        paho.Client
	log           *slog.Logger
	mu            sync.RWMutex
	connected     bool
	channels      map[string]struct{}
	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler
}

// New creates a new MQTT transport.
func New(cfg Config) *Transport {
	if cfg.Broker == "" {
		cfg.Broker = DefaultBroker
	}
	if cfg.Username == "" {
		cfg.Username = DefaultUsername
	}
	if cfg.Password == "" {
		cfg.Password = DefaultPassword
	}
	if cfg.Root == "" {
		cfg.Root = DefaultRoot
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Transport{
		cfg:      cfg,
		log:      cfg.Logger.WithGroup("mqtt"),
		channels: make(map[string]struct{}),
	}
}

// Start implements transport.Transport.
func (t *Transport) Start(ctx context.Context) error {
	clientID := randomString(23)

	opts := paho.NewClientOptions().
		AddBroker(t.cfg.Broker).
		SetUsername(t.cfg.Username).
		SetPassword(t.cfg.Password).
		SetClientID(clientID).
		SetOrderMatters(false).
		SetCleanSession(false).
		SetKeepAlive(30 * time.Second).
		SetResumeSubs(true).
		SetPingTimeout(5 * time.Second).
		SetAutoReconnect(true).
		SetMaxReconnectInterval(1 * time.Minute).
		SetConnectionLostHandler(t.onConnectionLost).
		SetReconnectingHandler(t.onReconnecting).
		SetOnConnectHandler(t.onConnected)

	t.client = paho.NewClient(opts)
	if token := t.client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	return nil
}

// Stop implements transport.Transport.
func (t *Transport) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		t.client.Disconnect(1000)
		t.connected = false
	}
	return nil
}

// IsConnected implements transport.Transport.
func (t *Transport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected && t.client != nil && t.client.IsConnected()
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

// AddChannel subscribes to a channel.
func (t *Transport) AddChannel(channelName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.channels[channelName] = struct{}{}

	if t.client != nil && t.client.IsConnected() {
		topic := t.getTopicForChannel(channelName) + "/+"
		t.client.Subscribe(topic, 0, t.handleMessage)
		t.log.Debug("subscribed to channel", "channel", channelName, "topic", topic)
	}
}

// SendPacket implements raw.RawTransport.
func (t *Transport) SendPacket(channel string, packet *pb.MeshPacket) error {
	if !t.IsConnected() {
		return errors.New("not connected")
	}

	se := &pb.ServiceEnvelope{
		ChannelId: channel,
		GatewayId: t.cfg.NodeID.String(),
		Packet:    packet,
	}

	data, err := proto.Marshal(se)
	if err != nil {
		return fmt.Errorf("marshalling service envelope: %w", err)
	}

	topic := t.getTopicForChannel(channel) + "/" + t.cfg.NodeID.String()
	token := t.client.Publish(topic, 0, false, data)
	if !token.WaitTimeout(10 * time.Second) {
		return errors.New("timeout publishing to MQTT")
	}
	return token.Error()
}

func (t *Transport) getTopicForChannel(channel string) string {
	return t.cfg.Root + ProtoTopic + channel
}

func (t *Transport) getChannelFromTopic(topic string) string {
	trimmed := strings.TrimPrefix(topic, t.cfg.Root+ProtoTopic)
	sepIndex := strings.Index(trimmed, "/")
	if sepIndex > 0 {
		return trimmed[:sepIndex]
	}
	return trimmed
}

func (t *Transport) handleMessage(_ paho.Client, message paho.Message) {
	t.mu.RLock()
	handler := t.packetHandler
	t.mu.RUnlock()

	if handler == nil {
		return
	}

	se := &pb.ServiceEnvelope{}
	if err := proto.Unmarshal(message.Payload(), se); err != nil {
		t.log.Error("failed to unmarshal service envelope", "error", err)
		return
	}

	if se.Packet == nil {
		return
	}

	channel := t.getChannelFromTopic(message.Topic())

	handler(transport.NetworkPacket{
		Packet:    se.Packet,
		Channel:   channel,
		Source:    transport.PacketSourceMQTT,
		GatewayID: se.GatewayId,
	})
}

func (t *Transport) onConnected(_ paho.Client) {
	t.mu.Lock()
	t.connected = true
	channels := make([]string, 0, len(t.channels))
	for ch := range t.channels {
		channels = append(channels, ch)
	}
	handler := t.stateHandler
	t.mu.Unlock()

	// Resubscribe to all channels
	for _, ch := range channels {
		topic := t.getTopicForChannel(ch) + "/+"
		t.client.Subscribe(topic, 0, t.handleMessage)
	}

	t.log.Info("connected to MQTT broker", "broker", t.cfg.Broker)

	if handler != nil {
		handler(t, transport.ListenerEventConnected)
	}
}

func (t *Transport) onConnectionLost(_ paho.Client, err error) {
	t.mu.Lock()
	t.connected = false
	handler := t.stateHandler
	t.mu.Unlock()

	t.log.Error("MQTT connection lost", "error", err)

	if handler != nil {
		handler(t, transport.ListenerEventDisconnected)
	}
}

func (t *Transport) onReconnecting(_ paho.Client, _ *paho.ClientOptions) {
	t.mu.RLock()
	handler := t.stateHandler
	t.mu.RUnlock()

	t.log.Info("reconnecting to MQTT broker")

	if handler != nil {
		handler(t, transport.ListenerEventReconnecting)
	}
}

func randomString(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}
