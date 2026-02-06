// Package tcp provides a TCP transport for connecting to Meshtastic devices.
package tcp

import (
	"context"
	"fmt"
	"net"

	"github.com/kabili207/meshtastic-go/transport/client"
	"github.com/kabili207/meshtastic-go/transport/stream"
)

const (
	// DefaultPort is the default TCP port for Meshtastic devices.
	DefaultPort = 4403
)

// Config holds the configuration for a TCP connection.
type Config struct {
	// Address is the TCP address to connect to (e.g., "192.168.1.100:4403").
	Address string
	// TransportConfig holds client transport configuration.
	TransportConfig client.TransportConfig
}

// Connect opens a TCP connection to a Meshtastic device and returns a client transport.
func Connect(ctx context.Context, cfg Config) (*client.Transport, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", cfg.Address, err)
	}

	streamConn, err := stream.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("creating stream connection: %w", err)
	}

	transport := client.NewTransport(streamConn, cfg.TransportConfig)

	if err := transport.Connect(ctx); err != nil {
		streamConn.Close()
		return nil, fmt.Errorf("connecting to device: %w", err)
	}

	return transport, nil
}

// ConnectSimple is a convenience function that connects with default settings.
func ConnectSimple(ctx context.Context, address string) (*client.Transport, error) {
	return Connect(ctx, Config{Address: address})
}
