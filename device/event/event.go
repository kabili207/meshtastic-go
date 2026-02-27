// Package event defines typed events emitted by a Meshtastic device node
// when decoded packets are processed. Consumers register handlers via
// [node.Node.OnEvent] and type-switch on the concrete event type.
package event

import (
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Handler is called for each event emitted by the node. Consumers should
// type-switch on the concrete event type (NodeInfoUpdated, TextMessage, etc.).
type Handler func(evt any)

// Event is the base for all device events. Every concrete event embeds this.
type Event struct {
	// ChannelName is the channel this packet was received on.
	// Set to "PKI" for PKI-encrypted direct messages.
	ChannelName string
	// From is the sender node ID.
	From core.NodeID
	// To is the destination node ID (may be BroadcastNodeID).
	To core.NodeID
	// Timestamp is the receive time (from MeshPacket.RxTime, or time.Now()).
	Timestamp time.Time
	// PacketID is the mesh packet ID.
	PacketID uint32
	// Portnum is the decoded application portnum.
	Portnum pb.PortNum
	// IsPKI is true if the packet was PKI-encrypted.
	IsPKI bool
	// RawData is the full decoded pb.Data, for consumers that need the raw payload.
	RawData *pb.Data
}

// NodeInfoUpdated is emitted when a NODEINFO_APP packet is processed.
type NodeInfoUpdated struct {
	Event
	User *pb.User
}

// PositionUpdated is emitted when a POSITION_APP packet is processed.
type PositionUpdated struct {
	Event
	Position *pb.Position
}

// TelemetryUpdated is emitted when a TELEMETRY_APP packet is processed.
type TelemetryUpdated struct {
	Event
	Telemetry *pb.Telemetry
}

// TextMessage is emitted when a TEXT_MESSAGE_APP packet is received.
type TextMessage struct {
	Event
	// Message is the text content.
	Message string
	// IsDM is true if the message is a direct message (not broadcast).
	IsDM bool
	// ReplyID is the packet ID this message is replying to, or 0.
	ReplyID uint32
	// Emoji is non-zero if this is a reaction (the emoji codepoint).
	Emoji uint32
}

// WaypointReceived is emitted when a WAYPOINT_APP packet is processed.
type WaypointReceived struct {
	Event
	// Waypoint is the decoded waypoint data.
	Waypoint *pb.Waypoint
	// IsDelete is true when the waypoint's expiration time is in the past,
	// indicating the sender wants to remove it.
	IsDelete bool
}

// NeighborInfoReceived is emitted when a NEIGHBORINFO_APP packet is processed.
type NeighborInfoReceived struct {
	Event
	// NeighborInfo contains the sender's neighbor list and metadata.
	NeighborInfo *pb.NeighborInfo
}

// MapReportReceived is emitted when a MAP_REPORT_APP packet is processed.
type MapReportReceived struct {
	Event
	// MapReport contains the node's map report data.
	MapReport *pb.MapReport
}

// TracerouteReceived is emitted when a TRACEROUTE_APP packet is processed.
type TracerouteReceived struct {
	Event
	// RouteDiscovery contains the route hops and SNR data.
	RouteDiscovery *pb.RouteDiscovery
	// IsRequest is true for traceroute requests, false for responses.
	IsRequest bool
}

// RoutingReceived is emitted when a ROUTING_APP packet is processed.
// This covers ACKs, NACKs, and other routing error notifications.
type RoutingReceived struct {
	Event
	// ErrorReason is the routing result. NONE indicates a successful ACK.
	ErrorReason pb.Routing_Error
	// OriginalPacketID is the packet ID this routing message is responding to.
	OriginalPacketID uint32
}

// PacketReceived is emitted for any successfully decoded packet whose portnum
// does not have a more specific event type. Useful as a catch-all.
type PacketReceived struct {
	Event
}
