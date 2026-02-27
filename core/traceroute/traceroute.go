// Package traceroute provides helpers for parsing and analyzing Meshtastic
// traceroute (route discovery) data.
package traceroute

import (
	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Hop represents a single hop in a traceroute route.
type Hop struct {
	// NodeID is the node at this hop. May be 0 for unknown hops.
	NodeID core.NodeID
	// SNR is the signal-to-noise ratio in dB at this hop.
	// Raw values in the protocol are stored as 4x the actual value.
	SNR float32
	// Unknown is true if this hop is a placeholder inserted to fill gaps
	// between known hops based on hop count math.
	Unknown bool
}

// ParseRoute extracts an ordered list of hops from a RouteDiscovery message.
// The returned slice represents the path from sender to receiver, with SNR
// values converted from the protocol's 4x encoding to actual dB values.
//
// Unknown hops (gaps in the route) are filled with placeholder entries where
// Unknown=true and NodeID=0.
func ParseRoute(rd *pb.RouteDiscovery, from, to core.NodeID) []Hop {
	if rd == nil {
		return nil
	}

	route := rd.Route
	snrBack := rd.SnrBack

	hops := make([]Hop, 0, len(route)+2)

	// Start with the sender.
	hops = append(hops, Hop{NodeID: from})

	// Add each intermediate hop.
	for i, nodeID := range route {
		hop := Hop{NodeID: core.NodeID(nodeID)}
		if i < len(snrBack) {
			hop.SNR = float32(snrBack[i]) / 4.0
		}
		hops = append(hops, hop)
	}

	// End with the receiver.
	hops = append(hops, Hop{NodeID: to})

	return hops
}

// HopCount returns the number of hops a packet has traversed, calculated
// from HopStart - HopLimit. Returns 0 if HopStart is not set.
func HopCount(pkt *pb.MeshPacket) int {
	if pkt.HopStart == 0 {
		return 0
	}
	count := int(pkt.HopStart) - int(pkt.HopLimit)
	if count < 0 {
		return 0
	}
	return count
}

// InsertUnknownHops fills gaps in a route based on the expected hop count.
// If the route has fewer intermediate nodes than expectedHops, unknown
// placeholder hops are inserted at the end of the intermediate section
// (before the final destination).
func InsertUnknownHops(hops []Hop, expectedHops int) []Hop {
	if len(hops) < 2 {
		return hops
	}

	// Intermediate hops are everything except first (sender) and last (receiver).
	intermediateCount := len(hops) - 2
	missing := expectedHops - intermediateCount - 1 // -1 because expectedHops includes the final hop

	if missing <= 0 {
		return hops
	}

	// Insert unknown hops before the final destination.
	result := make([]Hop, 0, len(hops)+missing)
	result = append(result, hops[:len(hops)-1]...) // everything except last
	for range missing {
		result = append(result, Hop{Unknown: true})
	}
	result = append(result, hops[len(hops)-1]) // final destination

	return result
}
