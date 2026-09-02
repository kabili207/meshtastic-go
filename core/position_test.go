package core

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

func chanWith(role pb.Channel_Role, psk []byte, precision uint32) *pb.Channel {
	return &pb.Channel{
		Role: role,
		Settings: &pb.ChannelSettings{
			Psk:            psk,
			ModuleSettings: &pb.ModuleSettings{PositionPrecision: precision},
		},
	}
}

func privateKey() []byte {
	k := make([]byte, len(crypto.DefaultKey))
	copy(k, crypto.DefaultKey)
	k[0] ^= 0xFF // differs outside the last byte, so not part of the default family
	return k
}

func TestChannelUsesPublicKey(t *testing.T) {
	defaultFamily := bytes.Clone(crypto.DefaultKey)
	defaultFamily[len(defaultFamily)-1] ^= 0x7F // only the last byte varies

	tests := []struct {
		name     string
		channels []*pb.Channel
		index    int
		want     bool
	}{
		{"default key is public", []*pb.Channel{chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 32)}, 0, true},
		{"default family member is public", []*pb.Channel{chanWith(pb.Channel_PRIMARY, defaultFamily, 32)}, 0, true},
		{"single byte psk is public", []*pb.Channel{chanWith(pb.Channel_PRIMARY, []byte{1}, 32)}, 0, true},
		{"empty psk on primary is public", []*pb.Channel{chanWith(pb.Channel_PRIMARY, nil, 32)}, 0, true},
		{"custom key is private", []*pb.Channel{chanWith(pb.Channel_PRIMARY, privateKey(), 32)}, 0, false},
		{"disabled channel is not public", []*pb.Channel{chanWith(pb.Channel_DISABLED, crypto.DefaultKey, 32)}, 0, false},
		{"index out of range", []*pb.Channel{chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 32)}, 5, false},
		{"negative index", []*pb.Channel{chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 32)}, -1, false},
		{
			"secondary inherits a private primary",
			[]*pb.Channel{
				chanWith(pb.Channel_PRIMARY, privateKey(), 32),
				chanWith(pb.Channel_SECONDARY, nil, 32),
			},
			1, false,
		},
		{
			"secondary inherits a public primary",
			[]*pb.Channel{
				chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 32),
				chanWith(pb.Channel_SECONDARY, nil, 32),
			},
			1, true,
		},
		{
			"secondary with its own private key ignores the primary",
			[]*pb.Channel{
				chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 32),
				chanWith(pb.Channel_SECONDARY, privateKey(), 32),
			},
			1, false,
		},
		{
			"secondary with no primary to inherit fails closed to public",
			[]*pb.Channel{chanWith(pb.Channel_SECONDARY, nil, 32)},
			0, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ChannelUsesPublicKey(tt.channels, tt.index); got != tt.want {
				t.Errorf("ChannelUsesPublicKey = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPositionPrecisionForChannel(t *testing.T) {
	tests := []struct {
		name     string
		channels []*pb.Channel
		want     uint32
	}{
		{"public channel is capped", []*pb.Channel{chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 32)}, MaxPositionPrecisionPublicKey},
		{"private channel keeps full precision", []*pb.Channel{chanWith(pb.Channel_PRIMARY, privateKey(), 32)}, 32},
		{"public channel below the cap is untouched", []*pb.Channel{chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 10)}, 10},
		{"public channel exactly at the cap is untouched", []*pb.Channel{chanWith(pb.Channel_PRIMARY, crypto.DefaultKey, 15)}, 15},
		{"disabled channel shares nothing", []*pb.Channel{chanWith(pb.Channel_DISABLED, privateKey(), 32)}, 0},
		{"zero precision shares nothing", []*pb.Channel{chanWith(pb.Channel_PRIMARY, privateKey(), 0)}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PositionPrecisionForChannel(tt.channels, 0); got != tt.want {
				t.Errorf("PositionPrecisionForChannel = %d, want %d", got, tt.want)
			}
		})
	}
}

// A channel with no module settings must report 0 rather than full precision, or a
// sharing-disabled channel leaks an exact location.
func TestPositionPrecisionForChannelFailsClosed(t *testing.T) {
	noModule := []*pb.Channel{{
		Role:     pb.Channel_PRIMARY,
		Settings: &pb.ChannelSettings{Psk: privateKey()},
	}}
	if got := PositionPrecisionForChannel(noModule, 0); got != 0 {
		t.Errorf("channel without module settings = %d, want 0", got)
	}

	noSettings := []*pb.Channel{{Role: pb.Channel_PRIMARY}}
	if got := PositionPrecisionForChannel(noSettings, 0); got != 0 {
		t.Errorf("channel without settings = %d, want 0", got)
	}
}

func TestFindPositionChannel(t *testing.T) {
	t.Run("picks the lowest sharing channel", func(t *testing.T) {
		channels := []*pb.Channel{
			chanWith(pb.Channel_PRIMARY, privateKey(), 0),
			chanWith(pb.Channel_SECONDARY, privateKey(), 16),
			chanWith(pb.Channel_SECONDARY, privateKey(), 32),
		}
		idx, ok := FindPositionChannel(channels)
		if !ok || idx != 1 {
			t.Errorf("FindPositionChannel = (%d, %v), want (1, true)", idx, ok)
		}
	})

	t.Run("reports false when nothing shares", func(t *testing.T) {
		channels := []*pb.Channel{
			chanWith(pb.Channel_PRIMARY, privateKey(), 0),
			chanWith(pb.Channel_DISABLED, privateKey(), 32),
		}
		if idx, ok := FindPositionChannel(channels); ok {
			t.Errorf("FindPositionChannel = (%d, true), want false", idx)
		}
	})

	t.Run("reports false for an empty table", func(t *testing.T) {
		if _, ok := FindPositionChannel(nil); ok {
			t.Error("FindPositionChannel(nil) reported a channel")
		}
	})
}

func TestApplyPositionPrecision(t *testing.T) {
	t.Run("zero precision clears everything but the time", func(t *testing.T) {
		pos := &pb.Position{
			LatitudeI:  proto.Int32(476226196),
			LongitudeI: proto.Int32(-1223981600),
			Altitude:   proto.Int32(120),
			SatsInView: 9,
			Time:       1700000000,
		}
		ApplyPositionPrecision(pos, 0)

		if pos.Time != 1700000000 {
			t.Errorf("Time = %d, want it preserved", pos.Time)
		}
		if pos.LatitudeI != nil || pos.LongitudeI != nil {
			t.Error("coordinates survived a zero-precision wipe")
		}
		if pos.Altitude != nil || pos.SatsInView != 0 || pos.PrecisionBits != 0 {
			t.Error("other locating fields survived a zero-precision wipe")
		}
	})

	t.Run("records the precision it applied", func(t *testing.T) {
		pos := &pb.Position{LatitudeI: proto.Int32(476226196), LongitudeI: proto.Int32(-1223981600)}
		ApplyPositionPrecision(pos, 16)

		if pos.PrecisionBits != 16 {
			t.Errorf("PrecisionBits = %d, want 16", pos.PrecisionBits)
		}
		if pos.GetLatitudeI() != 476217344 {
			t.Errorf("LatitudeI = %d, want 476217344", pos.GetLatitudeI())
		}
		if pos.GetLongitudeI() != -1223983104 {
			t.Errorf("LongitudeI = %d, want -1223983104", pos.GetLongitudeI())
		}
	})

	t.Run("full precision leaves coordinates alone", func(t *testing.T) {
		pos := &pb.Position{LatitudeI: proto.Int32(476226196), LongitudeI: proto.Int32(-1223981600)}
		ApplyPositionPrecision(pos, 32)

		if pos.GetLatitudeI() != 476226196 || pos.GetLongitudeI() != -1223981600 {
			t.Error("full precision altered the coordinates")
		}
		if pos.PrecisionBits != 32 {
			t.Errorf("PrecisionBits = %d, want 32", pos.PrecisionBits)
		}
	})

	t.Run("precision above 32 is clamped", func(t *testing.T) {
		pos := &pb.Position{LatitudeI: proto.Int32(476226196)}
		ApplyPositionPrecision(pos, 99)

		if pos.PrecisionBits != 32 {
			t.Errorf("PrecisionBits = %d, want 32", pos.PrecisionBits)
		}
		if pos.GetLatitudeI() != 476226196 {
			t.Error("clamped-to-32 precision altered the coordinate")
		}
	})

	// An unset coordinate must stay unset. Truncating a nil field through its zero
	// value would report a location at the center of the grid cell containing 0,0.
	t.Run("unset coordinates are not invented", func(t *testing.T) {
		pos := &pb.Position{Time: 42}
		ApplyPositionPrecision(pos, 16)

		if pos.LatitudeI != nil || pos.LongitudeI != nil {
			t.Errorf("invented a coordinate: lat=%v lon=%v", pos.LatitudeI, pos.LongitudeI)
		}
	})

	t.Run("nil position is a no-op", func(t *testing.T) {
		ApplyPositionPrecision(nil, 16)
	})
}
