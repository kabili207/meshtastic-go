package node

import (
	mathRand "math/rand/v2"
	"sync"
)

// packetIDGenerator produces firmware-matching packet IDs.
// The lower 10 bits are a monotonically incrementing counter.
// The upper 22 bits are randomized each call.
// This matches the Meshtastic firmware behavior (Router.cpp).
type packetIDGenerator struct {
	mu      sync.Mutex
	counter uint32
}

func (g *packetIDGenerator) next() uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.counter == 0 {
		g.counter = mathRand.Uint32()
	}

	g.counter++
	// Keep lower 10 bits of the increment, randomize upper 22 bits
	g.counter = (g.counter & 0x3FF) | (mathRand.Uint32() << 10)
	return g.counter
}
