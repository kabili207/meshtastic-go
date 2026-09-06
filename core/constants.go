package core

import (
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

const (
	// MaxHops is the firmware-enforced maximum number of hops a packet can traverse.
	MaxHops = 7

	// DefaultHopLimit is the default hop limit for outbound packets when not
	// explicitly configured.
	DefaultHopLimit = 3

	// MaxDataPayload is the maximum number of bytes that can be sent in a single
	// Data payload. This is one less than the firmware's DATA_PAYLOAD_LEN to
	// account for the portnum byte.
	MaxDataPayload = int(pb.Constants_DATA_PAYLOAD_LEN) - 1

	// MaxLongName is the maximum byte length of a node's long name.
	// Firmware 2.8 lowered this from 39; longer names still decode, but devices
	// truncate them before storing or rebroadcasting.
	MaxLongName = 24

	// MaxShortName is the maximum byte length of a node's short name.
	MaxShortName = 4

	// MaxNeighborsPerPacket is the maximum number of neighbors that can be
	// included in a single NeighborInfo packet.
	MaxNeighborsPerPacket = 10

	// PublicKeySize is the byte length of a node's X25519 identity public key.
	PublicKeySize = crypto.PublicKeySize

	// MaxLoraPayload is the largest frame a LoRa radio can carry, header included.
	MaxLoraPayload = 255

	// LoraHeaderLength is the size of the unencrypted packet header on the air.
	LoraHeaderLength = 16
)
