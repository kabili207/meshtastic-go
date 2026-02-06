package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// NodeID holds the node identifier. This is a uint32 value which uniquely identifies a node within a mesh.
type NodeID uint32

const (
	// BroadcastNodeID is the special NodeID used when broadcasting a packet to a channel.
	BroadcastNodeID NodeID = math.MaxUint32

	// BroadcastNodeIDNoLora is a special broadcast address that excludes LoRa transmission.
	// Used for MQTT-only broadcasts. This is ^all with the NO_LORA flag (0x40) cleared.
	BroadcastNodeIDNoLora NodeID = math.MaxUint32 ^ 0x40

	// ReservedNodeIDThreshold is the threshold at which NodeIDs are considered reserved. Random NodeIDs should not
	// be generated below this threshold.
	// Source: https://github.com/meshtastic/firmware/blob/d1ea58975755e146457a8345065e4ca357555275/src/mesh/NodeDB.cpp#L461
	reservedNodeIDThreshold NodeID = 4
)

// Uint32 returns the underlying uint32 value of the NodeID.
func (n NodeID) Uint32() uint32 {
	return uint32(n)
}

// String converts the NodeID to a hex formatted string.
// This is typically how NodeIDs are displayed in Meshtastic UIs.
func (n NodeID) String() string {
	return fmt.Sprintf("!%08x", uint32(n))
}

// Bytes converts the NodeID to a byte slice
func (n NodeID) Bytes() []byte {
	bytes := make([]byte, 4) // uint32 is 4 bytes
	binary.BigEndian.PutUint32(bytes, n.Uint32())
	return bytes
}

// DefaultLongName returns the default long node name based on the NodeID.
// Source: https://github.com/meshtastic/firmware/blob/d1ea58975755e146457a8345065e4ca357555275/src/mesh/NodeDB.cpp#L382
func (n NodeID) DefaultLongName() string {
	bytes := make([]byte, 4) // uint32 is 4 bytes
	binary.BigEndian.PutUint32(bytes, n.Uint32())
	return fmt.Sprintf("Meshtastic %04x", bytes[2:])
}

// DefaultShortName returns the default short node name based on the NodeID.
// Last two bytes of the NodeID represented in hex.
// Source: https://github.com/meshtastic/firmware/blob/d1ea58975755e146457a8345065e4ca357555275/src/mesh/NodeDB.cpp#L382
func (n NodeID) DefaultShortName() string {
	bytes := make([]byte, 4) // uint32 is 4 bytes
	binary.BigEndian.PutUint32(bytes, n.Uint32())
	return fmt.Sprintf("%04x", bytes[2:])
}

// RandomNodeID returns a randomised NodeID.
// It's recommended to call this the first time a node is started and persist the result.
//
// Hardware meshtastic nodes first try a NodeID of the last four bytes of the BLE MAC address. If that ID is already in
// use or invalid, a random NodeID is generated.
// Source: https://github.com/meshtastic/firmware/blob/d1ea58975755e146457a8345065e4ca357555275/src/mesh/NodeDB.cpp#L466
func RandomNodeID() (NodeID, error) {
	// Generates a random uint32 between reservedNodeIDThreshold and math.MaxUint32
	randomInt, err := rand.Int(
		rand.Reader,
		big.NewInt(
			int64(math.MaxUint32-reservedNodeIDThreshold.Uint32()),
		),
	)
	if err != nil {
		return NodeID(0), fmt.Errorf("reading entropy: %w", err)
	}
	r := uint32(randomInt.Uint64()) + reservedNodeIDThreshold.Uint32()
	return NodeID(r), nil
}

// ParseNodeID parses a NodeID from various string formats:
//   - "!abcd1234" (Meshtastic format with ! prefix)
//   - "0xabcd1234" (hex with 0x prefix)
//   - "abcd1234" (plain hex)
//   - "12345678" (decimal)
func ParseNodeID(s string) (NodeID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty node ID string")
	}

	// Handle !prefix format
	if strings.HasPrefix(s, "!") {
		s = s[1:]
		n, err := strconv.ParseUint(s, 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid node ID %q: %w", s, err)
		}
		return NodeID(n), nil
	}

	// Handle 0x prefix
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid node ID %q: %w", s, err)
		}
		return NodeID(n), nil
	}

	// Try hex first if it looks like hex (contains a-f)
	sLower := strings.ToLower(s)
	if strings.ContainsAny(sLower, "abcdef") {
		n, err := strconv.ParseUint(s, 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid node ID %q: %w", s, err)
		}
		return NodeID(n), nil
	}

	// Try decimal
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		// Fall back to hex for 8-char strings
		if len(s) == 8 {
			n, err = strconv.ParseUint(s, 16, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid node ID %q: %w", s, err)
			}
			return NodeID(n), nil
		}
		return 0, fmt.Errorf("invalid node ID %q: %w", s, err)
	}
	return NodeID(n), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for use with config parsers like Viper.
func (n *NodeID) UnmarshalText(text []byte) error {
	parsed, err := ParseNodeID(string(text))
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (n NodeID) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

// IsReservedID returns true if this is a reserved or broadcast NodeID.
func (n NodeID) IsReservedID() bool {
	return n < reservedNodeIDThreshold || n >= BroadcastNodeIDNoLora
}

// IsBroadcast returns true if this is any form of broadcast address.
func (n NodeID) IsBroadcast() bool {
	return n == BroadcastNodeID || n == BroadcastNodeIDNoLora
}

// GetNodeColor returns a consistent hex color string for this NodeID.
// Useful for UI display where each node should have a unique color.
func (n NodeID) GetNodeColor() string {
	// Use the node ID bytes to generate RGB values
	// This ensures the same node always gets the same color
	r := uint8((n >> 16) & 0xFF)
	g := uint8((n >> 8) & 0xFF)
	b := uint8(n & 0xFF)

	// Ensure colors aren't too dark or too light for readability
	// Clamp to range 64-223 for each channel
	clamp := func(v uint8) uint8 {
		if v < 64 {
			return v + 64
		}
		if v > 223 {
			return v - 32
		}
		return v
	}

	return fmt.Sprintf("#%02x%02x%02x", clamp(r), clamp(g), clamp(b))
}

// ToMacAddress returns a MAC address string derived from the NodeID.
// This creates a locally administered unicast MAC address.
func (n NodeID) ToMacAddress() string {
	bytes := n.Bytes()
	// Use 0x02 as the first octet (locally administered, unicast)
	// Then 0x00 as padding, followed by the 4 bytes of the NodeID
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3])
}
