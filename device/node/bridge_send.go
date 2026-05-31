package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/lora"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// EncryptionMode selects how an outbound packet payload is protected.
type EncryptionMode int

const (
	// EncryptNone sends the payload as cleartext on channel 0 (used for map
	// reports and other public broadcasts).
	EncryptNone EncryptionMode = iota
	// EncryptPSK encrypts the payload with the channel's shared key.
	EncryptPSK
	// EncryptPKI encrypts the payload with Curve25519 between sender and
	// recipient. Falls back to PSK if keys are unavailable.
	EncryptPKI
)

const (
	bitfieldOkToMQTT     = 1
	bitfieldWantResponse = 2
)

// bridgeSend describes a fully-specified outbound packet from a managed node.
type bridgeSend struct {
	from, to     core.NodeID
	portnum      pb.PortNum
	payload      []byte
	enc          EncryptionMode
	channel      string // channel name; empty uses the primary channel
	replyID      uint32
	requestID    uint32
	emoji        uint32
	wantResponse bool
	wantAck      bool
}

// sendAs builds, encrypts, paces, and transmits a packet on behalf of a managed
// node, returning the generated packet ID. It mirrors firmware semantics for
// the WantResponse/WantAck bitfield and priority.
func (b *BridgeNode) sendAs(ctx context.Context, s bridgeSend) (uint32, error) {
	if !b.cfg.IsManagedNode(s.from) {
		return 0, fmt.Errorf("node %s is not managed by this bridge", s.from)
	}
	if len(s.payload) > core.MaxDataPayload {
		return 0, fmt.Errorf("payload too large: %d bytes exceeds max %d", len(s.payload), core.MaxDataPayload)
	}

	bitfield := uint32(bitfieldOkToMQTT)
	data := &pb.Data{
		Portnum:   s.portnum,
		Payload:   s.payload,
		Bitfield:  &bitfield,
		RequestId: s.requestID,
		ReplyId:   s.replyID,
		Emoji:     s.emoji,
	}

	// The firmware only honors WantResponse for a few request portnums on a
	// unicast packet. Mirror that gating to avoid spurious response storms.
	if s.wantResponse && !s.to.IsBroadcast() &&
		(s.portnum == pb.PortNum_NODEINFO_APP ||
			s.portnum == pb.PortNum_POSITION_APP ||
			s.portnum == pb.PortNum_TRACEROUTE_APP) {
		data.WantResponse = true
		bf := bitfield | bitfieldWantResponse
		data.Bitfield = &bf
	}

	// Traceroute relies on WantAck to trigger firmware response handling.
	wantAck := s.wantAck || (s.portnum == pb.PortNum_TRACEROUTE_APP && s.wantResponse)

	packetID := b.base.packetIDs.next()
	pkt := &pb.MeshPacket{
		Id:        packetID,
		From:      s.from.Uint32(),
		To:        s.to.Uint32(),
		WantAck:   wantAck,
		RxTime:    uint32(time.Now().Unix()),
		Priority:  lora.GetPriority(data, wantAck),
		RelayNode: b.cfg.NodeID.Uint32() & 0xFF,
	}
	b.applyHopLimits(pkt, s.from)

	channelName := s.channel
	if channelName == "" {
		channelName = b.base.primaryChannel
	}

	switch s.enc {
	case EncryptNone:
		pkt.Channel = 0
		pkt.PayloadVariant = &pb.MeshPacket_Decoded{Decoded: data}

	case EncryptPSK:
		ch, ok := b.base.channels.LookupByName(channelName)
		if !ok {
			return 0, fmt.Errorf("unknown channel %q", channelName)
		}
		hash, _ := crypto.ChannelHash(ch.GetName(), ch.GetKeyBytes())
		pkt.Channel = hash
		raw, err := proto.Marshal(data)
		if err != nil {
			return 0, fmt.Errorf("marshalling data: %w", err)
		}
		enc, err := crypto.XOR(raw, ch.GetKeyBytes(), packetID, s.from.Uint32())
		if err != nil {
			return 0, fmt.Errorf("PSK encrypt: %w", err)
		}
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{Encrypted: enc}

	case EncryptPKI:
		if b.cfg.PrivateKeyForNode == nil || b.cfg.PublicKeyForNode == nil {
			return 0, errors.New("PKI key callbacks not configured")
		}
		priv := b.cfg.PrivateKeyForNode(s.from)
		if priv == nil {
			return 0, fmt.Errorf("no private key for %s", s.from)
		}
		pub := b.cfg.PublicKeyForNode(s.to)
		if pub == nil {
			return 0, fmt.Errorf("no public key for %s", s.to)
		}
		raw, err := proto.Marshal(data)
		if err != nil {
			return 0, fmt.Errorf("marshalling data: %w", err)
		}
		enc, err := crypto.EncryptCurve25519(raw, priv, pub, packetID, s.from.Uint32())
		if err != nil {
			return 0, fmt.Errorf("PKI encrypt: %w", err)
		}
		pkt.Channel = 0
		pkt.PkiEncrypted = true
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{Encrypted: enc}

	default:
		return 0, errors.New("unknown encryption mode")
	}

	// Pace sends so radio hardware has time to switch between TX and RX.
	b.base.sendMu.Lock()
	defer b.base.sendMu.Unlock()
	if !b.base.lastSend.IsZero() {
		if elapsed := time.Since(b.base.lastSend); elapsed < sendDelay {
			time.Sleep(sendDelay - elapsed)
		}
	}
	b.base.lastSend = time.Now()

	if err := b.base.transport.SendPacket(channelName, pkt); err != nil {
		return packetID, err
	}
	return packetID, nil
}

// applyHopLimits sets HopLimit/HopStart from the configured default, adding one
// extra hop when sending on behalf of a node other than the bridge itself.
func (b *BridgeNode) applyHopLimits(pkt *pb.MeshPacket, from core.NodeID) {
	pkt.HopLimit = b.base.hopLimit
	pkt.HopStart = b.base.hopLimit
	if from != b.cfg.NodeID {
		pkt.HopStart++
		pkt.HopLimit++
		if pkt.HopStart > core.MaxHops {
			pkt.HopStart = core.MaxHops
		}
		if pkt.HopLimit > core.MaxHops {
			pkt.HopLimit = core.MaxHops
		}
	}
}

// encModeForOption resolves the encryption mode from send options: PKI if
// requested, otherwise PSK.
func encModeFor(usePKI bool) EncryptionMode {
	if usePKI {
		return EncryptPKI
	}
	return EncryptPSK
}

// SendPositionAs broadcasts or unicasts a Position from a managed node and
// returns the packet ID. precisionBits encodes the location uncertainty; use
// lora.MetersToPrecisionBits to derive it. timestamp is the position fix time.
func (b *BridgeNode) SendPositionAs(ctx context.Context, from, to core.NodeID, latI, lonI int32, alt *int32, precisionBits uint32, timestamp time.Time, opts ...SendOption) (uint32, error) {
	o := applySendOptions(opts)
	now := time.Now().UTC()
	pos := &pb.Position{
		Time:          uint32(now.Unix()),
		Timestamp:     uint32(timestamp.Unix()),
		LatitudeI:     &latI,
		LongitudeI:    &lonI,
		PrecisionBits: precisionBits,
	}
	if alt != nil {
		pos.Altitude = alt
	}
	payload, err := proto.Marshal(pos)
	if err != nil {
		return 0, fmt.Errorf("marshalling position: %w", err)
	}
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum:      pb.PortNum_POSITION_APP,
		payload:      payload,
		enc:          encModeFor(o.usePKI),
		channel:      o.channel,
		wantResponse: o.wantResponse,
	})
}

// SendTelemetryAs sends an arbitrary Telemetry payload from a managed node.
func (b *BridgeNode) SendTelemetryAs(ctx context.Context, from, to core.NodeID, tel *pb.Telemetry, opts ...SendOption) (uint32, error) {
	o := applySendOptions(opts)
	payload, err := proto.Marshal(tel)
	if err != nil {
		return 0, fmt.Errorf("marshalling telemetry: %w", err)
	}
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum:   pb.PortNum_TELEMETRY_APP,
		payload:   payload,
		enc:       encModeFor(o.usePKI),
		channel:   o.channel,
		requestID: o.requestID,
	})
}

// SendDeviceTelemetryAs broadcasts device metrics built from the bridge start
// time (mains-powered, uptime since start).
func (b *BridgeNode) SendDeviceTelemetryAs(ctx context.Context, from, to core.NodeID, opts ...SendOption) (uint32, error) {
	return b.SendTelemetryAs(ctx, from, to, b.buildDeviceMetrics(), opts...)
}

// buildDeviceMetrics reports the bridge as mains-powered with uptime measured
// from the configured StartTime.
func (b *BridgeNode) buildDeviceMetrics() *pb.Telemetry {
	now := time.Now().UTC()
	uptime := uint32(now.Sub(b.cfg.StartTime).Abs().Seconds())
	battLevel := uint32(101) // >100 indicates mains power
	voltage := float32(5.0)
	return &pb.Telemetry{
		Time: uint32(now.Unix()),
		Variant: &pb.Telemetry_DeviceMetrics{
			DeviceMetrics: &pb.DeviceMetrics{
				BatteryLevel:  &battLevel,
				Voltage:       &voltage,
				UptimeSeconds: &uptime,
			},
		},
	}
}

// SendHostMetricsAs broadcasts host metrics obtained from the configured
// HostMetricsProvider. Returns an error if no provider is configured.
func (b *BridgeNode) SendHostMetricsAs(ctx context.Context, from, to core.NodeID, opts ...SendOption) (uint32, error) {
	if b.cfg.HostMetricsProvider == nil {
		return 0, errors.New("HostMetricsProvider not configured")
	}
	tel, err := b.cfg.HostMetricsProvider()
	if err != nil {
		return 0, fmt.Errorf("building host metrics: %w", err)
	}
	return b.SendTelemetryAs(ctx, from, to, tel, opts...)
}

// SendReactionAs sends an emoji reaction (a text message tagged as an emoji,
// replying to the target packet) from a managed node and returns the packet ID.
func (b *BridgeNode) SendReactionAs(ctx context.Context, from, to core.NodeID, targetPacketID uint32, emoji string, opts ...SendOption) (uint32, error) {
	o := applySendOptions(opts)
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum: pb.PortNum_TEXT_MESSAGE_APP,
		payload: []byte(emoji),
		enc:     encModeFor(o.usePKI),
		channel: o.channel,
		replyID: targetPacketID,
		emoji:   1,
	})
}

// SendNackAs sends a routing negative-acknowledgement from a managed node.
func (b *BridgeNode) SendNackAs(ctx context.Context, from, to core.NodeID, packetID uint32) error {
	routing := &pb.Routing{
		Variant: &pb.Routing_ErrorReason{ErrorReason: pb.Routing_GOT_NAK},
	}
	payload, err := proto.Marshal(routing)
	if err != nil {
		return fmt.Errorf("marshalling routing: %w", err)
	}
	_, err = b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum:   pb.PortNum_ROUTING_APP,
		payload:   payload,
		enc:       EncryptPSK,
		requestID: packetID,
	})
	return err
}

// RequestTracerouteAs sends a traceroute request from a managed node and returns
// the packet ID for correlating the eventual response. When sending on behalf of
// a node other than the bridge, the bridge seeds itself as the first hop.
func (b *BridgeNode) RequestTracerouteAs(ctx context.Context, from, to core.NodeID, opts ...SendOption) (uint32, error) {
	o := applySendOptions(opts)
	disco := &pb.RouteDiscovery{}
	if from != b.cfg.NodeID {
		disco.Route = []uint32{b.cfg.NodeID.Uint32()}
		disco.SnrTowards = []int32{0}
	}
	payload, err := proto.Marshal(disco)
	if err != nil {
		return 0, fmt.Errorf("marshalling route discovery: %w", err)
	}
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum:      pb.PortNum_TRACEROUTE_APP,
		payload:      payload,
		enc:          encModeFor(o.usePKI),
		channel:      o.channel,
		wantResponse: true,
	})
}

// SendMapReportAs broadcasts an unencrypted map report from a managed node. The
// bridge identity reports CLIENT_BASE; other managed nodes report CLIENT_MUTE.
// The modem preset is derived from the primary channel name when it matches a
// known preset.
func (b *BridgeNode) SendMapReportAs(ctx context.Context, from core.NodeID, longName, shortName string, latI, lonI int32, alt *int32, precisionBits, numNodes uint32) (uint32, error) {
	if latI == 0 || lonI == 0 {
		return 0, errors.New("a valid location is required")
	}

	role := pb.Config_DeviceConfig_CLIENT_MUTE
	if from == b.cfg.NodeID {
		role = pb.Config_DeviceConfig_CLIENT_BASE
	}

	// TODO: derive region from the MQTT root topic rather than hardcoding US.
	region := pb.Config_LoRaConfig_RegionCode_value["US"]
	presetName := strcase.ToScreamingSnake(b.base.primaryChannel)
	preset, hasDefaultChannel := pb.Config_LoRaConfig_ModemPreset_value[presetName]

	mr := &pb.MapReport{
		LongName:            longName,
		ShortName:           shortName,
		Role:                role,
		HwModel:             b.cfg.HwModel,
		Region:              pb.Config_LoRaConfig_RegionCode(region),
		HasDefaultChannel:   hasDefaultChannel,
		LatitudeI:           latI,
		LongitudeI:          lonI,
		PositionPrecision:   precisionBits,
		NumOnlineLocalNodes: numNodes,
	}
	if hasDefaultChannel {
		mr.ModemPreset = pb.Config_LoRaConfig_ModemPreset(preset)
	}
	if alt != nil {
		mr.Altitude = *alt
	}

	payload, err := proto.Marshal(mr)
	if err != nil {
		return 0, fmt.Errorf("marshalling map report: %w", err)
	}
	return b.sendAs(ctx, bridgeSend{
		from: from, to: core.BroadcastNodeID,
		portnum: pb.PortNum_MAP_REPORT_APP,
		payload: payload,
		enc:     EncryptNone,
	})
}

// buildNeighborInfo assembles a NeighborInfo payload, dropping the sender and
// reserved IDs and capping the list to the per-packet maximum.
func buildNeighborInfo(from core.NodeID, neighborIDs []core.NodeID, broadcastInterval uint32) *pb.NeighborInfo {
	neighbors := make([]*pb.Neighbor, 0, len(neighborIDs))
	for _, id := range neighborIDs {
		if id != from && id > core.ReservedNodeIDThreshold {
			neighbors = append(neighbors, &pb.Neighbor{NodeId: id.Uint32(), Snr: 0})
		}
	}
	if len(neighbors) > core.MaxNeighborsPerPacket {
		neighbors = neighbors[:core.MaxNeighborsPerPacket]
	}
	return &pb.NeighborInfo{
		NodeId:                    from.Uint32(),
		Neighbors:                 neighbors,
		LastSentById:              from.Uint32(),
		NodeBroadcastIntervalSecs: broadcastInterval,
	}
}

// SendNeighborInfoAs broadcasts a managed node's neighbor list.
func (b *BridgeNode) SendNeighborInfoAs(ctx context.Context, from core.NodeID, neighborIDs []core.NodeID, broadcastInterval uint32) (uint32, error) {
	payload, err := proto.Marshal(buildNeighborInfo(from, neighborIDs, broadcastInterval))
	if err != nil {
		return 0, fmt.Errorf("marshalling neighbor info: %w", err)
	}
	return b.sendAs(ctx, bridgeSend{
		from: from, to: core.BroadcastNodeIDNoLora,
		portnum: pb.PortNum_NEIGHBORINFO_APP,
		payload: payload,
		enc:     EncryptPSK,
	})
}

// SendNeighborInfoResponseAs replies to a neighbor info request as a managed node.
func (b *BridgeNode) SendNeighborInfoResponseAs(ctx context.Context, from, to core.NodeID, neighborIDs []core.NodeID, broadcastInterval, requestID uint32, opts ...SendOption) (uint32, error) {
	o := applySendOptions(opts)
	payload, err := proto.Marshal(buildNeighborInfo(from, neighborIDs, broadcastInterval))
	if err != nil {
		return 0, fmt.Errorf("marshalling neighbor info: %w", err)
	}
	return b.sendAs(ctx, bridgeSend{
		from: from, to: to,
		portnum:   pb.PortNum_NEIGHBORINFO_APP,
		payload:   payload,
		enc:       encModeFor(o.usePKI),
		channel:   o.channel,
		requestID: requestID,
	})
}
