# Meshtastic Go

Go library for interfacing with Meshtastic mesh networks.

> **Under heavy development.** Consider these contracts written with a half-eaten crayon; they *will* change.

## Module Structure

This repository contains two Go modules:

### Core (`github.com/kabili207/meshtastic-go/core`)

Core types and utilities with minimal dependencies:
- `generated/` - Generated protobuf message definitions
- `crypto/` - Encryption (AES-CTR, Curve25519 PKI)
- `dedupe/` - Packet deduplication
- `lora/` - LoRa signal quality utilities
- `node_id.go` - NodeID type

### Transport (`github.com/kabili207/meshtastic-go/transport`)

Transport implementations for connecting to devices and mesh networks:

**Client Transports** (connect to existing nodes):
- `serial/` - Serial port connections
- `tcp/` - TCP connections
- `client/` - Base client transport with handler registry

**Raw Transports** (act as virtual nodes):
- `mqtt/` - MQTT transport for mesh communication
- `udp/` - UDP multicast (firmware 2.6+)

**Utilities**:
- `stream/` - Meshtastic stream protocol
- `emulated/` - Virtual radio for testing

## Usage Examples

### Core only (protobufs + crypto)
```go
import (
    pb "github.com/kabili207/meshtastic-go/core/proto"
    "github.com/kabili207/meshtastic-go/core/crypto"
)

key, _ := crypto.ParseKey("AQ==")
data, err := crypto.TryDecode(packet, key)
```

### Serial client transport
```go
import (
    "context"
    pb "github.com/kabili207/meshtastic-go/core/proto"
    "github.com/kabili207/meshtastic-go/transport/serial"
)

ctx := context.Background()
client, _ := serial.ConnectSimple(ctx, "/dev/ttyUSB0")
client.Handle(&pb.MeshPacket{}, func(msg proto.Message) error {
    // handle mesh packet
    return nil
})
```

### MQTT raw transport
```go
import (
    "context"
    "github.com/kabili207/meshtastic-go/transport"
    "github.com/kabili207/meshtastic-go/transport/mqtt"
)

t := mqtt.New(mqtt.Config{
    Broker: "tcp://mqtt.meshtastic.org:1883",
    Root:   "msh/US",
})
t.AddChannel("LongFast")
t.SetPacketHandler(func(pkt transport.NetworkPacket) {
    // handle mesh packet
})
t.Start(context.Background())
```

## Regenerating Protobufs

```bash
cd core
go generate ./...
```

This fetches the latest protobuf definitions from the Meshtastic protobufs repository and regenerates the Go code.
