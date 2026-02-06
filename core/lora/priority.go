package lora

import (
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// GetPriority determines the appropriate packet priority based on the data portnum and ack requirements.
// This matches the firmware's priority logic.
func GetPriority(data *pb.Data, wantAck bool) pb.MeshPacket_Priority {
	if data == nil {
		if wantAck {
			return pb.MeshPacket_RELIABLE
		}
		return pb.MeshPacket_DEFAULT
	}

	switch data.Portnum {
	case pb.PortNum_ADMIN_APP, pb.PortNum_ROUTING_APP:
		// Admin and routing packets get high priority
		return pb.MeshPacket_ACK

	case pb.PortNum_TRACEROUTE_APP:
		// Traceroute gets lower priority to not interfere with normal traffic
		return pb.MeshPacket_MIN

	case pb.PortNum_POSITION_APP, pb.PortNum_NODEINFO_APP, pb.PortNum_TELEMETRY_APP:
		// Periodic/telemetry data gets background priority
		return pb.MeshPacket_BACKGROUND

	default:
		if wantAck {
			return pb.MeshPacket_RELIABLE
		}
		return pb.MeshPacket_DEFAULT
	}
}
