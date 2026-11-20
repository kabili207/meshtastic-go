package node

import (
	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// Automatic acks and naks for packets addressed to one of our identities,
// mirroring firmware's ReliableRouter::sniffReceived.

// hopsAway mirrors firmware's getHopsAway: how many hops a packet travelled, or
// -1 when that cannot be known. A zero hop_start is only trustworthy from a
// sender new enough to always set the bitfield (2.5+), which only decoded data
// shows.
func hopsAway(pkt *pb.MeshPacket, data *pb.Data) int {
	if pkt.HopStart == 0 && (data == nil || data.Bitfield == nil) {
		return -1
	}
	if pkt.HopStart < pkt.HopLimit {
		return -1
	}
	return int(pkt.HopStart - pkt.HopLimit)
}

// responseHopLimit mirrors RoutingModule::getHopLimitForResponse: the hops the
// request used plus a margin of two, capped at the configured limit unless the
// request itself needed more.
func responseHopLimit(pkt *pb.MeshPacket, data *pb.Data, configured uint32) uint32 {
	if used := hopsAway(pkt, data); used >= 0 {
		switch {
		case uint32(used) > configured:
			return uint32(used)
		case pkt.HopStart == 0:
			return 0
		case uint32(used)+2 < configured:
			return uint32(used) + 2
		}
	}
	return configured
}

// ackFor builds the ack firmware sends for a decoded want_ack packet addressed
// to one of our identities, or nil when none is due. A text DM's ack wants an
// ack itself, so the sender learns of delivery reliably. A reply only needs a
// zero-hop ack to stop the last hop retransmitting, and only when it arrived
// directly or through a chosen next hop.
func (b *baseNode) ackFor(pkt *pb.MeshPacket, data *pb.Data) *pb.MeshPacket {
	if !pkt.WantAck {
		return nil
	}
	switch {
	case data.Portnum == pb.PortNum_TEXT_MESSAGE_APP || data.Portnum == pb.PortNum_TEXT_MESSAGE_COMPRESSED_APP:
		return b.routingPacket(pkt, pb.Routing_NONE, responseHopLimit(pkt, data, b.hopLimit), true)
	case data.RequestId == 0 && data.ReplyId == 0:
		return b.routingPacket(pkt, pb.Routing_NONE, responseHopLimit(pkt, data, b.hopLimit), false)
	case hopsAway(pkt, data) == 0 || pkt.NextHop != 0:
		return b.routingPacket(pkt, pb.Routing_NONE, 0, false)
	}
	return nil
}

// nakFor builds the nak firmware sends for a want_ack packet addressed to one of
// our identities that we could not decode: PKI_UNKNOWN_PUBKEY when it was PKI from
// a node whose key we lack, so the sender sends us its NodeInfo, and NO_CHANNEL
// otherwise.
func (b *baseNode) nakFor(pkt *pb.MeshPacket) *pb.MeshPacket {
	if !pkt.WantAck {
		return nil
	}
	reason := pb.Routing_NO_CHANNEL
	if pkt.Channel == 0 && b.lookupPublicKey(core.NodeID(pkt.From)) == nil {
		reason = pb.Routing_PKI_UNKNOWN_PUBKEY
	}
	return b.routingPacket(pkt, reason, responseHopLimit(pkt, nil, b.hopLimit), false)
}

// routingPacket answers req with a Routing result from the identity it was
// addressed to. A zero hop limit still goes out at the default, since
// applyPacketDefaults reads zero as unset.
func (b *baseNode) routingPacket(req *pb.MeshPacket, reason pb.Routing_Error, hops uint32, wantAck bool) *pb.MeshPacket {
	payload, err := proto.Marshal(&pb.Routing{Variant: &pb.Routing_ErrorReason{ErrorReason: reason}})
	if err != nil {
		b.log.Error("marshalling routing response", "error", err)
		return nil
	}
	return &pb.MeshPacket{
		From:     req.To,
		To:       req.From,
		WantAck:  wantAck,
		HopLimit: hops,
		HopStart: hops,
		Priority: pb.MeshPacket_ACK,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{
			Portnum:   pb.PortNum_ROUTING_APP,
			Payload:   payload,
			RequestId: req.Id,
		}},
	}
}
