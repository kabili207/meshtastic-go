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
	WantAck       bool
	HopStart      uint32
	HopLimit      uint32
	RxSnr         float32
}

// responseEncryption picks the encryption mode and channel for a reply based on
// how the inbound packet arrived. PKI-decrypted packets ("PKI" channel) get a
// PKI reply; everything else replies with PSK on the same channel.
func responseEncryption(channelName string) (EncryptionMode, string) {
	if channelName == "PKI" {
		return EncryptPKI, ""
	}
	return EncryptPSK, channelName
}

// respondTelemetry answers a telemetry request addressed to a managed node,
// subject to a throttle, mirroring the firmware's request handling.
func (b *BridgeNode) respondTelemetry(evt eventContext, tel *pb.Telemetry) {
	to := evt.To // the managed node being queried
	from := evt.From

	if !b.cfg.IsManagedNode(to) {
		return
	}
	if !b.base.throttle.canRespond(to, pb.PortNum_TELEMETRY_APP) {
		b.base.log.Debug("skipping telemetry response due to throttle", "to", to, "from", from)
		return
	}
	b.base.log.Info("telemetry request received", "to", to, "from", from)

	enc, channel := responseEncryption(evt.ChannelName)
	opts := []SendOption{WithChannel(channel), WithRequestID(evt.PacketID)}
	if enc == EncryptPKI {
		opts = append(opts, WithPKI())
	}

	switch tel.Variant.(type) {
	case *pb.Telemetry_HostMetrics:
		if _, err := b.SendHostMetricsAs(context.Background(), to, from, opts...); err != nil {
			b.base.log.Error("failed to send host metrics response", "error", err)
		}
	default:
		// Device metrics for explicit device requests and empty requests.
		if _, err := b.SendTelemetryAs(context.Background(), to, from, b.buildDeviceMetrics(), opts...); err != nil {
			b.base.log.Error("failed to send telemetry response", "error", err)
		}
	}
}

// respondNeighborInfo answers a neighbor info request addressed to a managed
// node using the configured NeighborProvider, subject to a throttle.
func (b *BridgeNode) respondNeighborInfo(evt eventContext, ni *pb.NeighborInfo) {
	to := evt.To
	from := evt.From

	if !b.cfg.IsManagedNode(to) {
		return
	}

	// Ignore dummy/interceptable probes (a single neighbor with id=0, snr=0).
	if len(ni.Neighbors) == 1 && ni.Neighbors[0].NodeId == 0 && ni.Neighbors[0].Snr == 0 {
		b.base.log.Debug("ignoring dummy neighbor info request", "to", to, "from", from)
		return
	}
	if !b.base.throttle.canRespond(to, pb.PortNum_NEIGHBORINFO_APP) {
		b.base.log.Debug("skipping neighbor info response due to throttle", "to", to, "from", from)
		return
	}
	b.base.log.Info("neighbor info request received", "to", to, "from", from)

	var neighborIDs []core.NodeID
	if b.cfg.NeighborProvider != nil {
		neighborIDs = b.cfg.NeighborProvider(to)
	}

	enc, channel := responseEncryption(evt.ChannelName)
	opts := []SendOption{WithChannel(channel)}
	if enc == EncryptPKI {
		opts = append(opts, WithPKI())
	}
	if _, err := b.SendNeighborInfoResponseAs(context.Background(), to, from, neighborIDs, b.cfg.NeighborBroadcastInterval, evt.PacketID, opts...); err != nil {
		b.base.log.Error("failed to send neighbor info response", "error", err)
	}
}

// --- Traceroute ---

// handleTracerouteRequest answers a traceroute request on behalf of a managed
// destination, building the forward route (with placeholders for silent hops
// and the bridge inserted when relaying for another node) and sending it back.
func (b *BridgeNode) handleTracerouteRequest(evt eventContext, disco *pb.RouteDiscovery) {
	to := evt.To
	from := evt.From

	if !b.cfg.IsManagedNode(to) {
		return
	}

	if evt.WantAck {
		if err := b.SendAckAs(context.Background(), to, from, evt.PacketID); err != nil {
			b.base.log.Debug("failed to ack traceroute request", "error", err)
		}
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

	enc, channel := responseEncryption(evt.ChannelName)
	payload, err := proto.Marshal(disco)
	if err != nil {
		b.base.log.Error("failed to marshal traceroute response", "error", err)
		return
	}
	opts := bridgeSend{
		from: to, to: from,
		portnum:   pb.PortNum_TRACEROUTE_APP,
		payload:   payload,
		enc:       enc,
		channel:   channel,
		requestID: evt.PacketID,
	}
	if _, err := b.sendAs(context.Background(), opts); err != nil {
		b.base.log.Error("failed to send traceroute response", "error", err)
	}
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
	if evt.Via == 0 || evt.Via == evt.From {
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
