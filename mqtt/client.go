package mqtt

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const MQTTProtoTopic = "/2/e/"
const MQTTMapTopic = "/2/map/"
const MQTTPrivateTopic = MQTTProtoTopic + "PKI/"

type Client struct {
	server    string
	username  string
	password  string
	topicRoot string
	clientID  string
	client    mqtt.Client
	log       *slog.Logger
	sync.RWMutex
	channelHandlers map[string][]HandlerFunc
	mapHandlers     []HandlerFunc

	OnConnect        OnConnectHandler
	OnConnectionLost ConnectionLostHandler
	OnReconnecting   ReconnectHandler
}

type HandlerFunc func(message Message)

type ConnectionLostHandler func(error)

type OnConnectHandler func()

type ReconnectHandler func()

var DefaultClient = Client{
	server:          "tcp://mqtt.meshtastic.org:1883",
	username:        "meshdev",
	password:        "large4cats",
	topicRoot:       "msh", //TODO: this will need to change
	log:             slog.Default(),
	channelHandlers: make(map[string][]HandlerFunc),
	mapHandlers:     []HandlerFunc{},
}

func NewClient(url, username, password, rootTopic string) *Client {
	return &Client{
		server:          url,
		username:        username,
		password:        password,
		topicRoot:       rootTopic,
		log:             slog.Default(),
		channelHandlers: make(map[string][]HandlerFunc),
		mapHandlers:     []HandlerFunc{},
	}
}

func (c *Client) TopicRoot() string {
	return c.topicRoot
}

func (c *Client) Connect() error {
	var alphabet = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	c.clientID = randomString(23, alphabet)

	handler := c.log.Handler()

	mqtt.DEBUG = slog.NewLogLogger(handler, slog.LevelDebug)
	mqtt.WARN = slog.NewLogLogger(handler, slog.LevelWarn)
	mqtt.ERROR = slog.NewLogLogger(handler, slog.LevelError)
	mqtt.CRITICAL = slog.NewLogLogger(handler, slog.LevelError+4)

	opts := mqtt.NewClientOptions().
		AddBroker(c.server).
		SetUsername(c.username).
		SetOrderMatters(false).
		SetPassword(c.password).
		SetClientID(c.clientID).
		SetCleanSession(false)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetResumeSubs(true)
	//opts.SetDefaultPublishHandler(f)
	opts.SetPingTimeout(5 * time.Second)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(1 * time.Minute)
	opts.SetConnectionLostHandler(c.onConnectionLost)
	opts.SetReconnectingHandler(c.onReconnecting)
	opts.SetOnConnectHandler(c.onConnected)
	c.client = mqtt.NewClient(opts)
	if token := c.client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (c *Client) Disconnect() {
	if c.client != nil {
		c.client.Disconnect(1000)
	}
}

func (c *Client) IsConnected() bool {
	return c.client != nil && c.client.IsConnected()
}

// MQTT Message
type Message struct {
	Topic    string
	Payload  []byte
	Retained bool
}

// Publish a message to the broker
func (c *Client) Publish(m *Message) error {
	tok := c.client.Publish(m.Topic, 0, m.Retained, m.Payload)
	if !tok.WaitTimeout(10 * time.Second) {
		tok.Wait()
		return errors.New("timeout on mqtt publish")
	}
	if tok.Error() != nil {
		return tok.Error()
	}
	return nil
}

// Register a handler for messages on the specified channel
func (c *Client) Handle(channel string, h HandlerFunc) {
	c.Lock()
	defer c.Unlock()
	topic := c.GetFullTopicForChannel(channel)
	c.channelHandlers[channel] = append(c.channelHandlers[channel], h)
	c.client.Subscribe(topic+"/+", 0, c.handleBrokerMessage)
}

// Register a handler for messages on the specified channel
func (c *Client) HandleMap(h HandlerFunc) {
	c.Lock()
	defer c.Unlock()
	topic := c.topicRoot + MQTTMapTopic
	c.mapHandlers = append(c.mapHandlers, h)
	c.client.Subscribe(topic+"/+", 0, c.handleBrokerMessage)
}

func (c *Client) GetFullTopicForChannel(channel string) string {
	return c.topicRoot + MQTTProtoTopic + channel
}

func (c *Client) GetChannelFromTopic(topic string) string {
	trimmed := strings.TrimPrefix(topic, c.topicRoot+MQTTProtoTopic)
	sepIndex := strings.Index(trimmed, "/")
	if sepIndex > 0 {
		return trimmed[:sepIndex]
	}
	return trimmed
}
func (c *Client) handleBrokerMessage(client mqtt.Client, message mqtt.Message) {
	msg := Message{
		Topic:    message.Topic(),
		Payload:  message.Payload(),
		Retained: message.Retained(),
	}
	c.RLock()
	defer c.RUnlock()
	var chans []HandlerFunc
	if strings.HasSuffix(msg.Topic, MQTTMapTopic) {
		chans = c.mapHandlers
		if len(chans) == 0 {
			slog.Error("no map handlers found")
		}
	} else {
		channel := c.GetChannelFromTopic(msg.Topic)
		chans = c.channelHandlers[channel]
		if len(chans) == 0 {
			slog.Error("no handlers found", "topic", channel)
		}
	}
	for _, ch := range chans {
		go ch(msg)
	}
}

func (c *Client) SetLogger(logger *slog.Logger) {
	if logger == nil {
		c.log = slog.Default()
	} else {
		c.log = logger
	}
}

// SetOnConnectHandler sets the function to be called when the client is connected. Both
// at initial connection time and upon automatic reconnect.
func (o *Client) SetOnConnectHandler(onConn OnConnectHandler) {
	o.OnConnect = onConn
}

// SetConnectionLostHandler will set the OnConnectionLost callback to be executed
// in the case where the client unexpectedly loses connection with the MQTT broker.
func (o *Client) SetConnectionLostHandler(onLost ConnectionLostHandler) {
	o.OnConnectionLost = onLost
}

// SetReconnectingHandler sets the OnReconnecting callback to be executed prior
// to the client attempting a reconnect to the MQTT broker.
func (o *Client) SetReconnectingHandler(cb ReconnectHandler) {
	o.OnReconnecting = cb
}

func (c *Client) onConnectionLost(client mqtt.Client, err error) {
	if c.OnConnectionLost != nil {
		c.OnConnectionLost(err)
	} else {
		c.log.Error("mqtt connection lost", "err", err)
	}
}

func (c *Client) onReconnecting(client mqtt.Client, options *mqtt.ClientOptions) {
	if c.OnReconnecting != nil {
		c.OnReconnecting()
	} else {
		c.log.Info("mqtt reconnecting")
	}
}

func (c *Client) onConnected(client mqtt.Client) {
	if c.OnConnect != nil {
		c.OnConnect()
	} else {
		c.log.Info("connected to", "server", c.server)
	}
}
