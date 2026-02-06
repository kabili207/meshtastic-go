// Package serial provides a serial transport for connecting to Meshtastic devices.
package serial

import (
	"context"
	"fmt"

	"github.com/kabili207/meshtastic-go/transport/client"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"go.bug.st/serial"
)

const (
	// DefaultBaudRate is the default baud rate for Meshtastic serial connections.
	DefaultBaudRate = 115200
)

// Config holds the configuration for a serial connection.
type Config struct {
	// Port is the serial port path (e.g., "/dev/ttyUSB0" or "COM3").
	Port string
	// BaudRate is the serial baud rate. Defaults to 115200.
	BaudRate int
	// TransportConfig holds client transport configuration.
	TransportConfig client.TransportConfig
}

// Connect opens a serial connection to a Meshtastic device and returns a client transport.
func Connect(ctx context.Context, cfg Config) (*client.Transport, error) {
	baudRate := cfg.BaudRate
	if baudRate == 0 {
		baudRate = DefaultBaudRate
	}

	mode := &serial.Mode{
		BaudRate: baudRate,
	}

	port, err := serial.Open(cfg.Port, mode)
	if err != nil {
		return nil, fmt.Errorf("opening serial port: %w", err)
	}

	streamConn, err := stream.NewClientConn(port)
	if err != nil {
		port.Close()
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
func ConnectSimple(ctx context.Context, port string) (*client.Transport, error) {
	return Connect(ctx, Config{Port: port})
}
