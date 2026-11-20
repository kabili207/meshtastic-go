# Meshtastic Go

Go library for interfacing with Meshtastic mesh networks.

> **Under heavy development.** Consider these contracts written with a half-eaten crayon; they *will* change.

```bash
go get github.com/kabili207/meshtastic-go
```

Tracks Meshtastic firmware and protobufs 2.8. To reach 2.6 and 2.7 nodes over UDP, set `udp.Config.MulticastIP` to `udp.LegacyMulticastIP`.

## Packages

Everything lives in a single module, `github.com/kabili207/meshtastic-go`.

### `core/`

Protocol types and logic with no I/O:

- `proto/`: generated protobuf message definitions
- `crypto/`: channel encryption (AES-CTR), PKI (Curve25519 + AES-CCM), and XEdDSA packet signing
- `dedupe/`: packet deduplication
- `lora/`: region and modem preset tables, position precision, signal quality, and link budget math
- `traceroute/`: parsing route discovery results
- The package root has `NodeID`, channel definitions and the channel registry, positions, geofences, and roles

### `transport/`

Client transports connect to a real device through its client API:

- `serial/`: serial port connections
- `tcp/`: TCP connections
- `client/`: shared client transport with a handler registry
- `stream/`: the Meshtastic stream framing protocol used by serial and TCP

Raw transports carry mesh packets directly, so the Go side can act as a node of its own:

- `mqtt/`: MQTT
- `udp/`: UDP multicast
- `raw/`: the raw transport interface, plus `MultiTransport` for running several at once

### `device/`

The pieces for running a virtual node over a raw transport:

- `node/`: `Node` (a single virtual node) and `BridgeNode` (one transport serving many node identities)
- `nodedb/`: tracks known nodes from incoming packets
- `event/`: typed events for decoded packets
- `broadcast/`: periodic NodeInfo and position broadcasts
- `clientapi/`: a client API server, so the Meshtastic apps can connect to a virtual node

## Usage Examples

### Decrypting a channel packet

```go
import (
    "github.com/kabili207/meshtastic-go/core/crypto"
)

key, _ := crypto.ParseKey("AQ==")
data, err := crypto.TryDecode(packet, key)
```

### Serial client transport

```go
import (
    "context"

    "google.golang.org/protobuf/proto"

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

### Virtual node

```go
import (
    "context"

    "github.com/kabili207/meshtastic-go/core/crypto"
    pb "github.com/kabili207/meshtastic-go/core/proto"
    "github.com/kabili207/meshtastic-go/device/event"
    "github.com/kabili207/meshtastic-go/device/node"
    "github.com/kabili207/meshtastic-go/transport/udp"
)

pub, priv, _ := crypto.GenerateKeyPair()
key, _ := crypto.ParseKey("AQ==")

n, err := node.New(node.Config{
    Transport:  udp.New(udp.Config{}),
    PublicKey:  pub, // the node ID is derived from this
    PrivateKey: priv,
    LongName:   "Go Node",
    ShortName:  "GO",
    Channels: &pb.ChannelSet{
        Settings: []*pb.ChannelSettings{{Name: "LongFast", Psk: key}},
    },
    TCPListenAddr: ":4403", // lets the Meshtastic apps connect
})
if err != nil {
    return err
}
n.OnEvent(func(evt any) {
    if msg, ok := evt.(*event.TextMessage); ok {
        // msg.From, msg.Message, msg.Channel, ...
    }
})
return n.Run(context.Background())
```

## Regenerating Protobufs

Requires `protoc` and `protoc-gen-go` on your `PATH`.

```bash
go generate ./core
```

This checks out the newest tagged release in the `protobufs` submodule, then regenerates `core/proto`.
