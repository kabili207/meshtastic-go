package core

import (
	"bytes"

	"github.com/kabili207/meshtastic-go/core/crypto"
	"github.com/kabili207/meshtastic-go/core/lora"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// MaxPositionPrecisionPublicKey is the finest position precision firmware will transmit
// on a channel anyone can decrypt. Roughly a 700m latitude cell, which is also the
// ceiling MQTT map reports have always used.
const MaxPositionPrecisionPublicKey = 15

// ChannelUsesPublicKey reports whether a channel's effective key is one anybody can
// derive, meaning its traffic is public in practice. Used to cap position precision.
//
// channels is the node's channel table in index order, as the device stores it. A
// secondary channel with no key of its own inherits the primary's, so the whole table
// is needed rather than the single channel.
//
// This mirrors firmware's channelFileUsesPublicKey and fails closed: a malformed table
// that has no primary to inherit from is treated as public rather than private.
func ChannelUsesPublicKey(channels []*pb.Channel, index int) bool {
	if index < 0 || index >= len(channels) {
		return false
	}
	ch := channels[index]
	if ch == nil || ch.Settings == nil || ch.Role == pb.Channel_DISABLED {
		return false
	}

	psk := ch.Settings.Psk
	switch {
	case len(psk) == 0:
		// A secondary channel inherits the primary's key. On a primary, an empty key
		// means encryption is off, which is public by definition.
		if ch.Role != pb.Channel_SECONDARY {
			return true
		}
		for i, other := range channels {
			if other == nil || other.Role != pb.Channel_PRIMARY {
				continue
			}
			if i == index {
				return true
			}
			return ChannelUsesPublicKey(channels, i)
		}
		return true

	case len(psk) == 1:
		// Single-byte PSKs are indexes into the published default key family.
		return true

	default:
		// The default family varies only the last byte, so compare everything before it.
		return len(psk) == len(crypto.DefaultKey) &&
			bytes.Equal(psk[:len(psk)-1], crypto.DefaultKey[:len(crypto.DefaultKey)-1])
	}
}

// PositionPrecisionForChannel returns the precision, in significant coordinate bits,
// that a position may be sent with on the given channel. Zero means position sharing is
// off for that channel, which is also what a channel with no module settings reports:
// firmware fails closed here rather than assuming full precision.
//
// A channel whose configured precision exceeds MaxPositionPrecisionPublicKey is capped
// when its key is public. A channel configured below the cap keeps its own value, since
// the ceiling only ever coarsens.
func PositionPrecisionForChannel(channels []*pb.Channel, index int) uint32 {
	if index < 0 || index >= len(channels) {
		return 0
	}
	ch := channels[index]
	if ch == nil || ch.Role == pb.Channel_DISABLED || ch.Settings == nil {
		return 0
	}

	precision := ch.Settings.GetModuleSettings().GetPositionPrecision()
	if precision > MaxPositionPrecisionPublicKey && ChannelUsesPublicKey(channels, index) {
		precision = MaxPositionPrecisionPublicKey
	}
	return precision
}

// FindPositionChannel returns the index of the channel a position should be sent on:
// the lowest-indexed channel that permits any precision at all. Reports false when
// position sharing is disabled across every channel.
func FindPositionChannel(channels []*pb.Channel) (int, bool) {
	for i := range channels {
		if PositionPrecisionForChannel(channels, i) != 0 {
			return i, true
		}
	}
	return 0, false
}

// ApplyPositionPrecision coarsens a position in place to the given precision, and
// records the precision applied so receivers know how much to trust the coordinates.
//
// A precision of 0 clears the position entirely rather than merely zeroing the
// coordinates, keeping only the timestamp: every other field, altitude and satellite
// count included, narrows down a location too.
func ApplyPositionPrecision(position *pb.Position, precision uint32) {
	if position == nil {
		return
	}

	if precision == 0 {
		time := position.Time
		proto.Reset(position)
		position.Time = time
		return
	}

	if precision > 32 {
		precision = 32
	}
	position.PrecisionBits = precision

	if precision == 32 {
		return
	}
	// Truncate only what is actually set. Firmware's nanopb struct always carries a
	// coordinate, but here an unset one is nil, and coarsening it would invent a
	// location the sender never reported.
	if position.LatitudeI != nil {
		position.LatitudeI = proto.Int32(lora.TruncateCoordinate(*position.LatitudeI, precision))
	}
	if position.LongitudeI != nil {
		position.LongitudeI = proto.Int32(lora.TruncateCoordinate(*position.LongitudeI, precision))
	}
}
