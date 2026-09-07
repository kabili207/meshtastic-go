package core

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// ChannelDef defines a common interface for channel definitions from various sources.
// This abstracts over channels from device config, MQTT topics, or manual configuration.
//
// A channel's identity is its name and key together. The name alone is not enough:
// two channels may share a name with different keys, and on the LoRa wire only a
// one-byte hash of both travels, so the registry keeps every channel and lets a
// caller resolve by hash, by exact pair, or by name when the name is unique.
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

// SameChannel reports whether two definitions name the same channel: equal name
// and equal key bytes. Nil never matches.
func SameChannel(a, b ChannelDef) bool {
	if a == nil || b == nil {
		return false
	}
	return a.GetName() == b.GetName() && bytes.Equal(a.GetKeyBytes(), b.GetKeyBytes())
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
	return crypto.ChannelHash(c.Name, c.Key)
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

var (
	// ErrChannelNotFound reports a name that matches no registered channel.
	ErrChannelNotFound = errors.New("channel not found")
	// ErrChannelAmbiguous reports a name shared by more than one registered
	// channel, which only an exact name-and-key selection can resolve.
	ErrChannelAmbiguous = errors.New("channel name matches more than one registered channel")
)

// ChannelRegistry holds the channels a node knows, indexed by wire hash and by
// name. Both indexes may hold several channels per key: the one-byte wire hash
// collides, and names are not unique. It is safe for concurrent use, since
// channels can be added at runtime while the receive path performs lookups.
type ChannelRegistry struct {
	mu     sync.RWMutex
	order  []ChannelDef
	byHash map[uint32][]ChannelDef
	byName map[string][]ChannelDef
}

// NewChannelRegistry creates a new empty ChannelRegistry.
func NewChannelRegistry() *ChannelRegistry {
	return &ChannelRegistry{
		byHash: make(map[uint32][]ChannelDef),
		byName: make(map[string][]ChannelDef),
	}
}

// Register adds a channel. Registering the same name and key again replaces the
// earlier definition in place; a channel that merely shares a name or a hash with
// an existing one is kept alongside it.
func (r *ChannelRegistry) Register(ch ChannelDef) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.order {
		if SameChannel(existing, ch) {
			r.order[i] = ch
			r.byHash[ch.GetHash()] = replaceSame(r.byHash[ch.GetHash()], ch)
			r.byName[ch.GetName()] = replaceSame(r.byName[ch.GetName()], ch)
			return
		}
	}
	r.order = append(r.order, ch)
	r.byHash[ch.GetHash()] = append(r.byHash[ch.GetHash()], ch)
	r.byName[ch.GetName()] = append(r.byName[ch.GetName()], ch)
}

func replaceSame(list []ChannelDef, ch ChannelDef) []ChannelDef {
	for i, existing := range list {
		if SameChannel(existing, ch) {
			list[i] = ch
		}
	}
	return list
}

// Lookup finds the first registered channel with this wire hash. Hashes collide,
// so a receiver that may hold colliding channels should use LookupAll and try
// each, the way firmware does.
func (r *ChannelRegistry) Lookup(hash uint32) (ChannelDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := r.byHash[hash]
	if len(list) == 0 {
		return nil, false
	}
	return list[0], true
}

// LookupAll returns every registered channel with this wire hash, in
// registration order.
func (r *ChannelRegistry) LookupAll(hash uint32) []ChannelDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]ChannelDef(nil), r.byHash[hash]...)
}

// LookupName returns the name of the first registered channel with this hash,
// or an empty string if none.
func (r *ChannelRegistry) LookupName(hash uint32) string {
	if ch, ok := r.Lookup(hash); ok {
		return ch.GetName()
	}
	return ""
}

// ResolveByName finds the channel with this name. It fails with
// ErrChannelAmbiguous when more than one registered channel shares the name,
// rather than picking one, because a send on the wrong key is silent.
func (r *ChannelRegistry) ResolveByName(name string) (ChannelDef, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch list := r.byName[name]; len(list) {
	case 0:
		return nil, ErrChannelNotFound
	case 1:
		return list[0], nil
	default:
		return nil, ErrChannelAmbiguous
	}
}

// LookupByName is ResolveByName without the reason: false when the name is
// unknown or ambiguous.
func (r *ChannelRegistry) LookupByName(name string) (ChannelDef, bool) {
	ch, err := r.ResolveByName(name)
	return ch, err == nil
}

// LookupPair finds the channel with exactly this name and key. A short PSK is
// expanded before comparing, so the same key works in either form.
func (r *ChannelRegistry) LookupPair(name string, key []byte) (ChannelDef, bool) {
	want := crypto.ExpandShortPSK(key)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ch := range r.byName[name] {
		if bytes.Equal(ch.GetKeyBytes(), want) {
			return ch, true
		}
	}
	return nil, false
}

// All returns every registered channel in registration order.
func (r *ChannelRegistry) All() []ChannelDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]ChannelDef(nil), r.order...)
}
