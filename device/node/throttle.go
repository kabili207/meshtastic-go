package node

import (
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Default cooldown periods matching firmware behavior.
const (
	nodeInfoCooldown   = 5 * time.Minute
	telemetryCooldown  = 3 * time.Minute
	neighborCooldown   = 3 * time.Minute
	tracerouteCooldown = 30 * time.Second
)

type throttleKey struct {
	nodeID  core.NodeID
	portnum pb.PortNum
}

// requestThrottle prevents responding to WantResponse requests too frequently.
// Each (nodeID, portnum) pair has an independent cooldown.
type requestThrottle struct {
	mu   sync.Mutex
	last map[throttleKey]time.Time
}

func newRequestThrottle() *requestThrottle {
	return &requestThrottle{
		last: make(map[throttleKey]time.Time),
	}
}

// canRespond returns true if enough time has passed since the last response
// for this (nodeID, portnum) pair. If true, the timestamp is updated.
func (t *requestThrottle) canRespond(nodeID core.NodeID, portnum pb.PortNum) bool {
	cooldown := cooldownForPortnum(portnum)
	if cooldown == 0 {
		return true // no throttle for this portnum
	}

	key := throttleKey{nodeID: nodeID, portnum: portnum}

	t.mu.Lock()
	defer t.mu.Unlock()

	if lastTime, ok := t.last[key]; ok {
		if time.Since(lastTime) < cooldown {
			return false
		}
	}
	t.last[key] = time.Now()
	return true
}

func cooldownForPortnum(portnum pb.PortNum) time.Duration {
	switch portnum {
	case pb.PortNum_NODEINFO_APP:
		return nodeInfoCooldown
	case pb.PortNum_TELEMETRY_APP:
		return telemetryCooldown
	case pb.PortNum_NEIGHBORINFO_APP:
		return neighborCooldown
	case pb.PortNum_TRACEROUTE_APP:
		return tracerouteCooldown
	default:
		return 0
	}
}
