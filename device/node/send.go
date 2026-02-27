package node

import (
	"context"
	"fmt"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// SendOption configures optional fields on outgoing messages.
type SendOption func(*sendOptions)

type sendOptions struct {
	replyID  uint32
	emoji    uint32
	wantAck  bool
	usePKI   bool
	channel  string
}

// WithReplyID sets the reply ID, linking this message to a previous packet.
func WithReplyID(id uint32) SendOption {
	return func(o *sendOptions) { o.replyID = id }
}

// WithEmoji marks this message as an emoji reaction with the given codepoint.
func WithEmoji(codepoint uint32) SendOption {
	return func(o *sendOptions) { o.emoji = codepoint }
}

// WithWantAck requests delivery acknowledgement from the recipient.
func WithWantAck() SendOption {
	return func(o *sendOptions) { o.wantAck = true }
}

// WithPKI requests PKI (Curve25519) encryption instead of PSK channel encryption.
// Falls back to PSK if the recipient's public key is not known.
func WithPKI() SendOption {
	return func(o *sendOptions) { o.usePKI = true }
}

// WithChannel sends on a specific channel instead of the primary channel.
func WithChannel(name string) SendOption {
	return func(o *sendOptions) { o.channel = name }
}

// SendText sends a text message to the specified destination.
func (n *Node) SendText(ctx context.Context, to core.NodeID, message string, opts ...SendOption) error {
	if len(message) > core.MaxDataPayload {
		return fmt.Errorf("message too large: %d bytes exceeds max %d", len(message), core.MaxDataPayload)
	}

	o := applySendOptions(opts)

	data := &pb.Data{
		Portnum: pb.PortNum_TEXT_MESSAGE_APP,
		Payload: []byte(message),
		ReplyId: o.replyID,
		Emoji:   o.emoji,
	}

	if o.usePKI {
		return n.SendData(ctx, to, data, true)
	}

	pkt := &pb.MeshPacket{
		From:           n.cfg.NodeID.Uint32(),
		To:             to.Uint32(),
		WantAck:        o.wantAck,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: data},
	}
	return n.sendPacket(ctx, pkt, o.channel)
}

// SendAck sends a routing ACK for the given packet ID.
func (n *Node) SendAck(ctx context.Context, to core.NodeID, packetID uint32) error {
	return n.sendRoutingResponse(ctx, to, packetID, pb.Routing_NONE)
}

// SendNack sends a routing NACK for the given packet ID.
func (n *Node) SendNack(ctx context.Context, to core.NodeID, packetID uint32) error {
	return n.sendRoutingResponse(ctx, to, packetID, pb.Routing_GOT_NAK)
}

func (n *Node) sendRoutingResponse(ctx context.Context, to core.NodeID, packetID uint32, errReason pb.Routing_Error) error {
	routing := &pb.Routing{
		Variant: &pb.Routing_ErrorReason{
			ErrorReason: errReason,
		},
	}
	routingBytes, err := proto.Marshal(routing)
	if err != nil {
		return fmt.Errorf("marshalling routing: %w", err)
	}
	pkt := &pb.MeshPacket{
		From:     n.cfg.NodeID.Uint32(),
		To:       to.Uint32(),
		Priority: pb.MeshPacket_ACK,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum:   pb.PortNum_ROUTING_APP,
				Payload:   routingBytes,
				RequestId: packetID,
			},
		},
	}
	return n.sendPacket(ctx, pkt, "")
}

// SendWaypoint sends a waypoint to the specified destination on the given channel.
func (n *Node) SendWaypoint(ctx context.Context, to core.NodeID, waypoint *pb.Waypoint, opts ...SendOption) error {
	o := applySendOptions(opts)

	wpBytes, err := proto.Marshal(waypoint)
	if err != nil {
		return fmt.Errorf("marshalling waypoint: %w", err)
	}
	if len(wpBytes) > core.MaxDataPayload {
		return fmt.Errorf("waypoint too large: %d bytes exceeds max %d", len(wpBytes), core.MaxDataPayload)
	}
	pkt := &pb.MeshPacket{
		From:    n.cfg.NodeID.Uint32(),
		To:      to.Uint32(),
		WantAck: o.wantAck,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_WAYPOINT_APP,
				Payload: wpBytes,
			},
		},
	}
	return n.sendPacket(ctx, pkt, o.channel)
}

// SendNeighborInfo broadcasts neighbor information. The neighbor list is
// automatically truncated to MaxNeighborsPerPacket and self-references are
// filtered out.
func (n *Node) SendNeighborInfo(ctx context.Context, neighbors []*pb.Neighbor) error {
	filtered := make([]*pb.Neighbor, 0, len(neighbors))
	for _, nb := range neighbors {
		if core.NodeID(nb.NodeId) != n.cfg.NodeID && nb.NodeId > 1 {
			filtered = append(filtered, nb)
		}
	}
	if len(filtered) > core.MaxNeighborsPerPacket {
		filtered = filtered[:core.MaxNeighborsPerPacket]
	}

	ni := &pb.NeighborInfo{
		NodeId:           n.cfg.NodeID.Uint32(),
		Neighbors:        filtered,
		LastSentById:     n.cfg.NodeID.Uint32(),
	}
	niBytes, err := proto.Marshal(ni)
	if err != nil {
		return fmt.Errorf("marshalling neighbor info: %w", err)
	}
	pkt := &pb.MeshPacket{
		From:     n.cfg.NodeID.Uint32(),
		To:       core.BroadcastNodeID.Uint32(),
		Priority: pb.MeshPacket_BACKGROUND,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_NEIGHBORINFO_APP,
				Payload: niBytes,
			},
		},
	}
	return n.sendPacket(ctx, pkt, "")
}

// RequestTraceroute sends a traceroute request to the specified node.
// The response will arrive as a TracerouteReceived event.
func (n *Node) RequestTraceroute(ctx context.Context, to core.NodeID) error {
	rd := &pb.RouteDiscovery{}
	rdBytes, err := proto.Marshal(rd)
	if err != nil {
		return fmt.Errorf("marshalling route discovery: %w", err)
	}
	pkt := &pb.MeshPacket{
		From: n.cfg.NodeID.Uint32(),
		To:   to.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum:      pb.PortNum_TRACEROUTE_APP,
				Payload:      rdBytes,
				WantResponse: true,
			},
		},
	}
	return n.sendPacket(ctx, pkt, "")
}

// SendMapReport broadcasts a map report built from this node's configuration.
// Map reports are sent unencrypted as broadcast packets.
func (n *Node) SendMapReport(ctx context.Context) error {
	mr := &pb.MapReport{
		LongName:    n.cfg.LongName,
		ShortName:   n.cfg.ShortName,
		Role:        pb.Config_DeviceConfig_CLIENT_MUTE,
		HwModel:     n.cfg.HwModel,
		LatitudeI:   n.cfg.PositionLatitudeI,
		LongitudeI:  n.cfg.PositionLongitudeI,
		Altitude:    n.cfg.PositionAltitude,
	}
	mrBytes, err := proto.Marshal(mr)
	if err != nil {
		return fmt.Errorf("marshalling map report: %w", err)
	}
	pkt := &pb.MeshPacket{
		From:     n.cfg.NodeID.Uint32(),
		To:       core.BroadcastNodeID.Uint32(),
		Priority: pb.MeshPacket_BACKGROUND,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_MAP_REPORT_APP,
				Payload: mrBytes,
			},
		},
	}
	return n.sendPacket(ctx, pkt, "")
}

func applySendOptions(opts []SendOption) sendOptions {
	var o sendOptions
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
