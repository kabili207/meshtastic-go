// Package raw provides the interface for raw transports that act as virtual nodes.
package raw

import (
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
)

// RawTransport extends the base Transport interface with raw transport functionality.
// Raw transports act as virtual nodes on the mesh network, typically via MQTT or UDP.
type RawTransport interface {
	transport.Transport
	// SendPacket sends a mesh packet on the specified channel.
	SendPacket(channel string, packet *pb.MeshPacket) error
	// AddChannel subscribes to a channel. Required for MQTT, no-op for UDP.
	AddChannel(channelName string)
}
