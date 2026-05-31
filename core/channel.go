package core

import (
	"encoding/base64"
	"sync"

	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// ChannelDef defines a common interface for channel definitions from various sources.
// This abstracts over channels from device config, MQTT topics, or manual configuration.
type ChannelDef interface {
	// GetName returns the channel name.
	GetName() string

	// GetKeyString returns the channel key as a base64 string.
	GetKeyString() string

	// GetKeyBytes returns the channel key as raw bytes.
	// Short PSKs are automatically expanded to full 16-byte keys.
	GetKeyBytes() []byte

	// GetHash returns the channel hash used for routing.
	GetHash() uint32
}

// Channel is a simple implementation of ChannelDef.
type Channel struct {
	Name string
	Key  []byte
}

// NewChannel creates a new Channel with the given name and key.
// The key can be a base64-encoded string or "AQ==" style short PSK.
func NewChannel(name, keyStr string) (*Channel, error) {
	key, err := crypto.ParseKey(keyStr)
	if err != nil {
		return nil, err
	}
	return &Channel{Name: name, Key: key}, nil
}

// NewChannelWithKey creates a new Channel with raw key bytes.
func NewChannelWithKey(name string, key []byte) *Channel {
	return &Channel{Name: name, Key: crypto.ExpandShortPSK(key)}
}

// GetName returns the channel name.
func (c *Channel) GetName() string {
	return c.Name
}

// GetKeyString returns the channel key as a base64 string.
// If the key can be compacted to a short PSK, it will be.
func (c *Channel) GetKeyString() string {
	compacted := crypto.TryCompactKey(c.Key)
	return base64.StdEncoding.EncodeToString(compacted)
}

// GetKeyBytes returns the channel key as raw bytes.
func (c *Channel) GetKeyBytes() []byte {
	return c.Key
}

// GetHash returns the channel hash used for routing.
func (c *Channel) GetHash() uint32 {
	hash, _ := crypto.ChannelHash(c.Name, c.Key)
	return hash
}

// ChannelFromSettings creates a Channel from a protobuf ChannelSettings.
func ChannelFromSettings(settings *pb.ChannelSettings) *Channel {
	if settings == nil {
		return nil
	}

	name := settings.Name
	key := settings.Psk

	// Use default key for primary channel with empty/default PSK
	if len(key) == 0 {
		key = crypto.DefaultKey
	} else {
		key = crypto.ExpandShortPSK(key)
	}

	return &Channel{Name: name, Key: key}
}

// ChannelRegistry maintains a mapping of channel hashes to channel definitions.
// This is useful for looking up channel names from packet hashes. It is safe
// for concurrent use, since channels can be added at runtime while the receive
// path performs lookups.
type ChannelRegistry struct {
	mu       sync.RWMutex
	channels map[uint32]ChannelDef
}

// NewChannelRegistry creates a new empty ChannelRegistry.
func NewChannelRegistry() *ChannelRegistry {
	return &ChannelRegistry{
		channels: make(map[uint32]ChannelDef),
	}
}

// Register adds a channel to the registry.
func (r *ChannelRegistry) Register(ch ChannelDef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[ch.GetHash()] = ch
}

// Lookup finds a channel by its hash.
func (r *ChannelRegistry) Lookup(hash uint32) (ChannelDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ch, ok := r.channels[hash]
	return ch, ok
}

// LookupName returns the channel name for a hash, or empty string if not found.
func (r *ChannelRegistry) LookupName(hash uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if ch, ok := r.channels[hash]; ok {
		return ch.GetName()
	}
	return ""
}

// LookupByName finds a channel by its name.
func (r *ChannelRegistry) LookupByName(name string) (ChannelDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ch := range r.channels {
		if ch.GetName() == name {
			return ch, true
		}
	}
	return nil, false
}

// All returns all registered channels.
func (r *ChannelRegistry) All() []ChannelDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ChannelDef, 0, len(r.channels))
	for _, ch := range r.channels {
		result = append(result, ch)
	}
	return result
}
