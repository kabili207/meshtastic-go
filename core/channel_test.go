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
