package node

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// eventContext bundles a decoded event with the raw-packet fields the request
// responders need (hop counts and SNR) that are not part of event.Event.
type eventContext struct {
	From, To, Via core.NodeID
	PacketID      uint32
	ChannelName   string
	Channel       core.ChannelDef
	WantAck       bool
	HopStart      uint32
	HopLimit      uint32
	RxSnr         float32
}

// replyChannel sends a reply on the exact channel the request came in on, so a
// name shared by several channels still gets the right key. A PKI request has no
// channel; its reply goes out under PKI anyway wherever firmware would use it.
func replyChannel(evt eventContext) SendOption {
	if evt.Channel != nil {
		return WithChannelDef(evt.Channel)
	}
	if evt.ChannelName == "PKI" {
		return WithChannel("")
	}
	return WithChannel(evt.ChannelName)
}

// respondTelemetry answers a telemetry request addressed to a managed node,
// subject to a throttle, mirroring the firmware's request handling. It reports
// whether a reply went out.
func (b *BridgeNode) respondTelemetry(evt eventContext, tel *pb.Telemetry) bool {
	to := evt.To // the managed node being queried
	from := evt.From

	if !b.cfg.IsManagedNode(to) {
		return false
	}
	if !b.base.throttle.canRespond(to, pb.PortNum_TELEMETRY_APP) {
		b.base.log.Debug("skipping telemetry response due to throttle", "to", to, "from", from)
		return false
	}
	b.base.log.Info("telemetry request received", "to", to, "from", from)

	opts := []SendOption{replyChannel(evt), WithRequestID(evt.PacketID)}

	switch tel.Variant.(type) {
	case *pb.Telemetry_HostMetrics:
		if _, err := b.SendHostMetricsAs(context.Background(), to, from, opts...); err != nil {
			b.base.log.Error("failed to send host metrics response", "error", err)
			return false
		}
	default:
		// Device metrics for explicit device requests and empty requests.
		if _, err := b.SendTelemetryAs(context.Background(), to, from, b.buildDeviceMetrics(), opts...); err != nil {
			b.base.log.Error("failed to send telemetry response", "error", err)
			return false
		}
	}
	return true
}

// respondNeighborInfo answers a neighbor info request addressed to a managed
// node using the configured NeighborProvider, subject to a throttle. It reports
// whether a reply went out.
func (b *BridgeNode) respondNeighborInfo(evt eventContext, ni *pb.NeighborInfo) bool {
	to := evt.To
	from := evt.From

	if !b.cfg.IsManagedNode(to) {
		return false
	}

	// Ignore dummy/interceptable probes (a single neighbor with id=0, snr=0).
	if len(ni.Neighbors) == 1 && ni.Neighbors[0].NodeId == 0 && ni.Neighbors[0].Snr == 0 {
		b.base.log.Debug("ignoring dummy neighbor info request", "to", to, "from", from)
		return false
	}
	if !b.base.throttle.canRespond(to, pb.PortNum_NEIGHBORINFO_APP) {
		b.base.log.Debug("skipping neighbor info response due to throttle", "to", to, "from", from)
		return false
	}
	b.base.log.Info("neighbor info request received", "to", to, "from", from)

	var neighborIDs []core.NodeID
	if b.cfg.NeighborProvider != nil {
		neighborIDs = b.cfg.NeighborProvider(to)
	}

	opts := []SendOption{replyChannel(evt)}
	if _, err := b.SendNeighborInfoResponseAs(context.Background(), to, from, neighborIDs, b.cfg.NeighborBroadcastInterval, evt.PacketID, opts...); err != nil {
		b.base.log.Error("failed to send neighbor info response", "error", err)
		return false
	}
	return true
}

// --- Traceroute ---

// handleTracerouteRequest answers a traceroute request on behalf of a managed
// destination, building the forward route (with placeholders for silent hops
// and the bridge inserted when relaying for another node) and sending it back.
// It reports whether a reply went out.
func (b *BridgeNode) handleTracerouteRequest(evt eventContext, disco *pb.RouteDiscovery) bool {
	to := evt.To
	from := evt.From

	if !b.cfg.IsManagedNode(to) {
		return false
	}

	// Insert placeholders for hops that did not add themselves (older firmware
	// or nodes lacking the channel key).
	b.insertUnknownHops(evt, disco, true)

	// Add the gateway node to the forward route if it isn't already present.
	b.addGatewayToRoute(evt, disco, true)

	// When relaying for a managed node other than the bridge, the bridge is the
	// real last hop before that node, on both routes.
	if to != b.cfg.NodeID {
		b.addNodeToRouteIfMissing(disco, b.cfg.NodeID, 0, true)
		b.addNodeToRouteIfMissing(disco, b.cfg.NodeID, 0, false)
	}

	// Final SNR entry for the destination.
	disco.SnrTowards = append(disco.SnrTowards, 0)

	b.logRoute(disco, from, to)

	payload, err := proto.Marshal(disco)
	if err != nil {
		b.base.log.Error("failed to marshal traceroute response", "error", err)
		return false
	}
	opts := bridgeSend{
		from: to, to: from,
		portnum:    pb.PortNum_TRACEROUTE_APP,
		payload:    payload,
		enc:        EncryptAuto,
		channelDef: evt.Channel,
		requestID:  evt.PacketID,
	}
	if evt.ChannelName != "PKI" {
		opts.channel = evt.ChannelName
	}
	if _, err := b.sendAs(context.Background(), opts); err != nil {
		b.base.log.Error("failed to send traceroute response", "error", err)
		return false
	}
	return true
}

// handleTracerouteResponse builds the return route for a traceroute response
// travelling back to the originating managed node.
func (b *BridgeNode) handleTracerouteResponse(evt eventContext, disco *pb.RouteDiscovery) {
	to := evt.To

	if !b.cfg.IsManagedNode(to) {
		return
	}

	b.insertUnknownHops(evt, disco, false)
	b.addGatewayToRoute(evt, disco, false)

	if to != b.cfg.NodeID {
		b.addNodeToRouteIfMissing(disco, b.cfg.NodeID, 0, false)
	}

	disco.SnrBack = append(disco.SnrBack, 0)
}

// insertUnknownHops adds placeholder entries for hops that did not record
// themselves, keeping the SNR list aligned to the route length.
func (b *BridgeNode) insertUnknownHops(evt eventContext, disco *pb.RouteDiscovery, forward bool) {
	route := &disco.Route
	snr := &disco.SnrTowards
	if !forward {
		route = &disco.RouteBack
		snr = &disco.SnrBack
	}

	if evt.HopStart == 0 || evt.HopLimit > evt.HopStart {
		return
	}
	hopsTaken := int(evt.HopStart - evt.HopLimit)

	for i := len(*route); i < hopsTaken; i++ {
		*route = append(*route, core.BroadcastNodeID.Uint32())
	}
	for len(*snr) < len(*route) {
		*snr = append(*snr, math.MinInt8) // SNR unknown
	}
}

// addGatewayToRoute adds the delivering gateway to the route if it is a distinct
// node not already present.
func (b *BridgeNode) addGatewayToRoute(evt eventContext, disco *pb.RouteDiscovery, forward bool) {
	// Over radio/UDP, Via is only the relay's low byte. That isn't a node ID,
	// and insertUnknownHops has already accounted for the hop.
	if evt.Via.Uint32() <= 0xFF || evt.Via == evt.From {
		return
	}
	b.addNodeToRouteIfMissing(disco, evt.Via, int32(evt.RxSnr*4), forward)
}

// addNodeToRouteIfMissing appends a node (and its SNR) to a route if absent.
func (b *BridgeNode) addNodeToRouteIfMissing(disco *pb.RouteDiscovery, nodeID core.NodeID, snr int32, forward bool) {
	id := nodeID.Uint32()
	if forward {
		if !slices.Contains(disco.Route, id) {
			disco.Route = append(disco.Route, id)
			disco.SnrTowards = append(disco.SnrTowards, snr)
		}
		return
	}
	if !slices.Contains(disco.RouteBack, id) {
		disco.RouteBack = append(disco.RouteBack, id)
		disco.SnrBack = append(disco.SnrBack, snr)
	}
}

func (b *BridgeNode) logRoute(disco *pb.RouteDiscovery, origin, dest core.NodeID) {
	var route strings.Builder
	fmt.Fprintf(&route, "0x%x --> ", origin.Uint32())
	for i := range disco.Route {
		if i < len(disco.SnrTowards) && disco.SnrTowards[i] != math.MinInt8 {
			fmt.Fprintf(&route, "0x%x (%.2fdB) --> ", disco.Route[i], float32(disco.SnrTowards[i])/4)
		} else {
			fmt.Fprintf(&route, "0x%x (?dB) --> ", disco.Route[i])
		}
	}
	if n := len(disco.SnrTowards); n > 0 && disco.SnrTowards[n-1] != math.MinInt8 {
		fmt.Fprintf(&route, "0x%x (%.2fdB)", dest.Uint32(), float32(disco.SnrTowards[n-1])/4)
	} else {
		fmt.Fprintf(&route, "0x%x (?dB)", dest.Uint32())
	}
	b.base.log.Info("traceroute request received", "from", origin, "to", dest, "route", route.String())
}
