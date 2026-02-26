module github.com/kabili207/meshtastic-go/device

go 1.24.0

toolchain go1.24.1

replace (
	github.com/kabili207/meshtastic-go/core => ../core
	github.com/kabili207/meshtastic-go/transport => ../transport
)

require (
	github.com/kabili207/meshtastic-go/core v0.0.0
	github.com/kabili207/meshtastic-go/transport v0.0.0-00010101000000-000000000000
	golang.org/x/sync v0.19.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/pion/dtls/v3 v3.0.6 // indirect
	golang.org/x/crypto v0.47.0 // indirect
)
