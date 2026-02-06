module github.com/kabili207/meshtastic-go/transport

go 1.24.0

toolchain go1.24.1

require (
	github.com/eclipse/paho.mqtt.golang v1.5.1
	github.com/kabili207/meshtastic-go/core v0.0.0
	github.com/stretchr/testify v1.11.1
	go.bug.st/serial v1.6.4
	golang.org/x/sync v0.17.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/creack/goselect v0.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/pion/dtls/v3 v3.0.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/kabili207/meshtastic-go/core => ../core
