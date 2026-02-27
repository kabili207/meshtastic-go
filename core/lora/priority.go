package lora

import (
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// GetPriority determines the appropriate packet priority based on the data
// portnum and ack requirements. This mirrors the firmware's fixPriority()
// function in MeshPacketQueue.cpp.
func GetPriority(data *pb.Data, wantAck bool) pb.MeshPacket_Priority {
	pri := pb.MeshPacket_DEFAULT
	if wantAck {
		pri = pb.MeshPacket_RELIABLE
	}

	if data != nil {
		switch data.Portnum {
		case pb.PortNum_ROUTING_APP:
			return pb.MeshPacket_ACK
		case pb.PortNum_TEXT_MESSAGE_APP, pb.PortNum_ADMIN_APP:
			return pb.MeshPacket_HIGH
		default:
			if data.RequestId != 0 {
				return pb.MeshPacket_RESPONSE
			}
			if data.WantResponse {
				return pb.MeshPacket_RELIABLE
			}
		}
	}

	return pri
}
