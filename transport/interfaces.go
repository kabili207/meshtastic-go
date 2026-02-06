// Package transport provides transport interfaces and implementations for
// communicating with Meshtastic devices and mesh networks.
package transport

import (
	"context"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Transport is the base interface for all transport implementations.
type Transport interface {
	// Start begins the transport's connection and message handling.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the transport.
	Stop() error
	// IsConnected returns true if the transport is currently connected.
	IsConnected() bool
	// SetPacketHandler sets the callback for incoming mesh packets.
	SetPacketHandler(fn PacketHandler)
	// SetStateHandler sets the callback for transport state changes.
	SetStateHandler(fn StateHandler)
}

// PacketHandler is called when a mesh packet is received.
type PacketHandler func(NetworkPacket)

// StateHandler is called when the transport state changes.
type StateHandler func(transport Transport, event ListenerEvent)

// ListenerEvent represents transport state change events.
type ListenerEvent int

const (
	// ListenerEventConnected is fired when the transport connects.
	ListenerEventConnected ListenerEvent = iota
	// ListenerEventDisconnected is fired when the transport disconnects.
	ListenerEventDisconnected
	// ListenerEventReconnecting is fired when the transport is attempting to reconnect.
	ListenerEventReconnecting
	// ListenerEventError is fired when an error occurs.
	ListenerEventError
)

// NetworkPacket represents a mesh packet with additional metadata.
type NetworkPacket struct {
	// Packet is the underlying mesh packet.
	Packet *pb.MeshPacket
	// Channel is the channel ID/name where this packet was received.
	Channel string
	// Source indicates where this packet came from.
	Source PacketSource
	// GatewayID is the node ID of the gateway that received this packet (for MQTT).
	GatewayID string
}

// PacketSource indicates where a packet originated from.
type PacketSource int

const (
	// PacketSourceRadio indicates the packet came from a local radio connection.
	PacketSourceRadio PacketSource = iota
	// PacketSourceMQTT indicates the packet came from MQTT.
	PacketSourceMQTT
	// PacketSourceUDP indicates the packet came from UDP multicast.
	PacketSourceUDP
)

func (s PacketSource) String() string {
	switch s {
	case PacketSourceRadio:
		return "radio"
	case PacketSourceMQTT:
		return "mqtt"
	case PacketSourceUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func (e ListenerEvent) String() string {
	switch e {
	case ListenerEventConnected:
		return "connected"
	case ListenerEventDisconnected:
		return "disconnected"
	case ListenerEventReconnecting:
		return "reconnecting"
	case ListenerEventError:
		return "error"
	default:
		return "unknown"
	}
}
