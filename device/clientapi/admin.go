package clientapi

import (
	"fmt"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

func (s *Server) handleAdminMessage(conn *stream.Conn, packet *pb.MeshPacket, decoded *pb.Data) error {
	admin := &pb.AdminMessage{}
	if err := proto.Unmarshal(decoded.Payload, admin); err != nil {
		return fmt.Errorf("unmarshalling admin: %w", err)
	}

	switch admin.PayloadVariant.(type) {
	case *pb.AdminMessage_GetChannelRequest:
		resp := &pb.AdminMessage{
			PayloadVariant: &pb.AdminMessage_GetChannelResponse{
				GetChannelResponse: &pb.Channel{
					Index:    0,
					Settings: &pb.ChannelSettings{},
					Role:     pb.Channel_DISABLED,
				},
			},
		}
		respBytes, err := proto.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshalling response: %w", err)
		}
		return conn.Write(&pb.FromRadio{
			PayloadVariant: &pb.FromRadio_Packet{
				Packet: &pb.MeshPacket{
					Id:   s.cfg.NextPacketID(),
					From: s.cfg.NodeID.Uint32(),
					To:   s.cfg.NodeID.Uint32(),
					PayloadVariant: &pb.MeshPacket_Decoded{
						Decoded: &pb.Data{
							Portnum:   pb.PortNum_ADMIN_APP,
							Payload:   respBytes,
							RequestId: packet.Id,
						},
					},
				},
			},
		})
	}
	return nil
}
