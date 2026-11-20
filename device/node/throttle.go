package node

import (
	"sync"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Default cooldown periods matching firmware behavior.
const (
	telemetryCooldown  = 3 * time.Minute
	neighborCooldown   = 3 * time.Minute
	tracerouteCooldown = 30 * time.Second
	positionCooldown   = 3 * time.Minute
)

type throttleKey struct {
	nodeID  core.NodeID
	portnum pb.PortNum
}

// NodeInfoModule's limits on NodeInfo replies.
const (
	nodeInfoReplySuppress = 12 * time.Hour
	// nodeInfoFloor is firmware's 30-minute base. Firmware stretches it on a mesh
	// of more than 40 online nodes, by a factor that depends on the modem preset;
	// we model neither.
	nodeInfoFloor = 30 * time.Minute
	// nodeInfoUrgentFloor is the shorter floor for a NodeInfo sent in answer to a
	// PKI_UNKNOWN_PUBKEY nak.
	nodeInfoUrgentFloor = time.Minute
	// nodeInfoAskedPrune is the size past which stale requesters are dropped.
	nodeInfoAskedPrune = 1024
)

// requestThrottle prevents responding to WantResponse requests too frequently.
// Each (nodeID, portnum) pair has an independent cooldown. NodeInfo has its own
// limits, mirroring firmware's NodeInfoModule.
type requestThrottle struct {
	mu   sync.Mutex
	last map[throttleKey]time.Time

	nodeInfoAsked map[[2]core.NodeID]time.Time // (responder, requester)
	nodeInfoSent  map[core.NodeID]time.Time
}

func newRequestThrottle() *requestThrottle {
	return &requestThrottle{
		last:          make(map[throttleKey]time.Time),
		nodeInfoAsked: make(map[[2]core.NodeID]time.Time),
		nodeInfoSent:  make(map[core.NodeID]time.Time),
	}
}

// canReplyNodeInfo applies NodeInfoModule's limits to a NodeInfo request from
// requester to our identity responder: one reply per requester in 12 hours, and
// none within 30 minutes of any NodeInfo responder sent. Like firmware it notes
// the request even when suppressing the reply, so a node that keeps asking more
// often than the window keeps being ignored.
func (t *requestThrottle) canReplyNodeInfo(responder, requester core.NodeID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	key := [2]core.NodeID{responder, requester}
	last, asked := t.nodeInfoAsked[key]
	t.nodeInfoAsked[key] = now
	if len(t.nodeInfoAsked) > nodeInfoAskedPrune {
		for k, at := range t.nodeInfoAsked {
			if now.Sub(at) >= nodeInfoReplySuppress {
				delete(t.nodeInfoAsked, k)
			}
		}
	}
	if asked && now.Sub(last) < nodeInfoReplySuppress {
		return false
	}
	return !t.nodeInfoSentWithin(responder, nodeInfoFloor, now)
}

// canSendNodeInfoUrgently applies the shorter floor firmware uses for a NodeInfo
// sent because a peer lacks our key.
func (t *requestThrottle) canSendNodeInfoUrgently(responder core.NodeID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.nodeInfoSentWithin(responder, nodeInfoUrgentFloor, time.Now())
}

// noteNodeInfoSent records that responder sent a NodeInfo, broadcast or reply,
// which starts the floor for the next reply.
func (t *requestThrottle) noteNodeInfoSent(responder core.NodeID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodeInfoSent[responder] = time.Now()
}

func (t *requestThrottle) nodeInfoSentWithin(responder core.NodeID, d time.Duration, now time.Time) bool {
	sent, ok := t.nodeInfoSent[responder]
	return ok && now.Sub(sent) < d
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
	case pb.PortNum_TELEMETRY_APP:
		return telemetryCooldown
	case pb.PortNum_NEIGHBORINFO_APP:
		return neighborCooldown
	case pb.PortNum_TRACEROUTE_APP:
		return tracerouteCooldown
	case pb.PortNum_POSITION_APP:
		return positionCooldown
	default:
		return 0
	}
}
