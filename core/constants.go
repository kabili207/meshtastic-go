package core

import pb "github.com/kabili207/meshtastic-go/core/proto"

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
	MaxLongName = 39

	// MaxShortName is the maximum byte length of a node's short name.
	MaxShortName = 4

	// MaxNeighborsPerPacket is the maximum number of neighbors that can be
	// included in a single NeighborInfo packet.
	MaxNeighborsPerPacket = 10
)
