package core

import (
	"testing"

	"github.com/kabili207/meshtastic-go/core/crypto"
)

func TestNewChannel(t *testing.T) {
	ch, err := NewChannel("LongFast", "AQ==")
	if err != nil {
		t.Fatalf("NewChannel error: %v", err)
	}

	if ch.GetName() != "LongFast" {
		t.Errorf("GetName() = %q, want %q", ch.GetName(), "LongFast")
	}

	if len(ch.GetKeyBytes()) != 16 {
		t.Errorf("GetKeyBytes() len = %d, want 16", len(ch.GetKeyBytes()))
	}

	keyStr := ch.GetKeyString()
	if keyStr == "" {
		t.Error("GetKeyString() returned empty")
	}

	hash := ch.GetHash()
	if hash == 0 {
		t.Error("GetHash() returned 0")
	}
}

func TestNewChannelWithKey(t *testing.T) {
	ch := NewChannelWithKey("test", crypto.DefaultKey)

	if ch.GetName() != "test" {
		t.Errorf("GetName() = %q, want %q", ch.GetName(), "test")
	}

	if len(ch.GetKeyBytes()) != 16 {
		t.Errorf("GetKeyBytes() len = %d, want 16", len(ch.GetKeyBytes()))
	}
}

func TestChannelRegistry(t *testing.T) {
	reg := NewChannelRegistry()

	ch1, _ := NewChannel("LongFast", "AQ==")
	ch2, _ := NewChannel("ShortFast", "Ag==")

	reg.Register(ch1)
	reg.Register(ch2)

	// Lookup by hash
	found, ok := reg.Lookup(ch1.GetHash())
	if !ok {
		t.Error("Lookup failed for registered channel")
	}
	if found.GetName() != "LongFast" {
		t.Errorf("Lookup returned wrong channel: %q", found.GetName())
	}

	// LookupName
	name := reg.LookupName(ch2.GetHash())
	if name != "ShortFast" {
		t.Errorf("LookupName() = %q, want %q", name, "ShortFast")
	}

	// Unknown hash
	name = reg.LookupName(0xdeadbeef)
	if name != "" {
		t.Errorf("LookupName(unknown) = %q, want empty", name)
	}

	// All
	all := reg.All()
	if len(all) != 2 {
		t.Errorf("All() len = %d, want 2", len(all))
	}
}

func TestChannelRegistrySameNameDifferentKeys(t *testing.T) {
	reg := NewChannelRegistry()
	a, _ := NewChannel("Shared", "AQ==")
	b, _ := NewChannel("Shared", "Ag==")
	reg.Register(a)
	reg.Register(b)

	if _, err := reg.ResolveByName("Shared"); err != ErrChannelAmbiguous {
		t.Errorf("ResolveByName on a shared name: err = %v, want ErrChannelAmbiguous", err)
	}
	if _, ok := reg.LookupByName("Shared"); ok {
		t.Error("LookupByName picked one of two same-name channels")
	}
	if _, err := reg.ResolveByName("Nope"); err != ErrChannelNotFound {
		t.Errorf("ResolveByName on an unknown name: err = %v, want ErrChannelNotFound", err)
	}

	got, ok := reg.LookupPair("Shared", b.GetKeyBytes())
	if !ok || !SameChannel(got, b) {
		t.Error("LookupPair did not return the channel with the matching key")
	}
	// A short PSK resolves to the same channel as its expanded form.
	if got, ok := reg.LookupPair("Shared", []byte{2}); !ok || !SameChannel(got, b) {
		t.Error("LookupPair did not expand a short PSK before comparing")
	}
	if _, ok := reg.LookupPair("Shared", []byte{9}); ok {
		t.Error("LookupPair matched a key that is not registered")
	}
	if len(reg.All()) != 2 {
		t.Errorf("All() len = %d, want 2", len(reg.All()))
	}
}

func TestChannelRegistryHashCollision(t *testing.T) {
	reg := NewChannelRegistry()
	// Same one-byte hash: XOR of name and key bytes is the same for both.
	a := NewChannelWithKey("ab", []byte{0x01})
	b := NewChannelWithKey("ba", []byte{0x01})
	if a.GetHash() != b.GetHash() {
		t.Fatalf("test setup: hashes differ (%x, %x)", a.GetHash(), b.GetHash())
	}
	reg.Register(a)
	reg.Register(b)

	all := reg.LookupAll(a.GetHash())
	if len(all) != 2 {
		t.Fatalf("LookupAll returned %d channels for a colliding hash, want 2", len(all))
	}
	if first, _ := reg.Lookup(a.GetHash()); !SameChannel(first, a) {
		t.Error("Lookup did not return the first registered channel")
	}
}

func TestChannelRegistryRegisterReplacesSameChannel(t *testing.T) {
	reg := NewChannelRegistry()
	a, _ := NewChannel("LongFast", "AQ==")
	again, _ := NewChannel("LongFast", "AQ==")
	reg.Register(a)
	reg.Register(again)

	if n := len(reg.All()); n != 1 {
		t.Errorf("re-registering the same channel produced %d entries, want 1", n)
	}
	if n := len(reg.LookupAll(a.GetHash())); n != 1 {
		t.Errorf("re-registering the same channel produced %d hash entries, want 1", n)
	}
}

func TestSameChannel(t *testing.T) {
	a, _ := NewChannel("X", "AQ==")
	b, _ := NewChannel("X", "AQ==")
	c, _ := NewChannel("X", "Ag==")
	d, _ := NewChannel("Y", "AQ==")
	if !SameChannel(a, b) || SameChannel(a, c) || SameChannel(a, d) || SameChannel(a, nil) || SameChannel(nil, nil) {
		t.Error("SameChannel mis-compared")
	}
}
