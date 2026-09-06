package core

import (
	"errors"
	"fmt"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// MeshBeaconHasOffer reports whether a beacon advertises a channel, region, or
// preset, as opposed to carrying only text. Firmware caches an offer for the
// client app to act on and never applies one itself.
func MeshBeaconHasOffer(b *pb.MeshBeacon) bool {
	return b != nil && (b.OfferChannel != nil || b.OfferRegion != pb.Config_LoRaConfig_UNSET || b.OfferPreset != nil)
}

// ValidateMeshBeacon checks the limits firmware enforces before a beacon is
// sent. A receiving node decodes into fixed-size buffers, so an over-long field
// is not truncated there: the whole beacon fails to decode and is dropped.
func ValidateMeshBeacon(b *pb.MeshBeacon) error {
	if b == nil {
		return errors.New("nil beacon")
	}
	if len(b.Message) > MaxMeshBeaconMessage {
		return fmt.Errorf("beacon message is %d bytes, max %d", len(b.Message), MaxMeshBeaconMessage)
	}
	if ch := b.OfferChannel; ch != nil {
		if len(ch.Name) > MaxChannelName {
			return fmt.Errorf("offered channel name is %d bytes, max %d", len(ch.Name), MaxChannelName)
		}
		if len(ch.Psk) > MaxChannelPSK {
			return fmt.Errorf("offered channel PSK is %d bytes, max %d", len(ch.Psk), MaxChannelPSK)
		}
	}
	if b.Message == "" && !MeshBeaconHasOffer(b) {
		return errors.New("beacon carries neither a message nor an offer")
	}
	return nil
}
