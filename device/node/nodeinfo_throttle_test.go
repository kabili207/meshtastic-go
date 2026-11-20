package node

import (
	"testing"
	"time"

	"github.com/kabili207/meshtastic-go/core"
)

// backdate moves every NodeInfo timestamp d into the past.
func (t *requestThrottle) backdate(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, at := range t.nodeInfoAsked {
		t.nodeInfoAsked[k] = at.Add(-d)
	}
	for k, at := range t.nodeInfoSent {
		t.nodeInfoSent[k] = at.Add(-d)
	}
}

// Mirrors NodeInfoModule: one reply per requester in 12 hours, and none within
// 30 minutes of any NodeInfo we sent.
func TestNodeInfoReplyLimits(t *testing.T) {
	const us, a, b = core.NodeID(1), core.NodeID(0xA), core.NodeID(0xB)

	t.Run("one reply per requester in 12 hours", func(t *testing.T) {
		th := newRequestThrottle()
		if !th.canReplyNodeInfo(us, a) {
			t.Fatal("first request refused")
		}
		th.noteNodeInfoSent(us)
		th.backdate(time.Hour)
		if th.canReplyNodeInfo(us, a) {
			t.Error("replied to the same requester within 12 hours")
		}
		if !th.canReplyNodeInfo(us, b) {
			t.Error("a new requester was refused once the floor had passed")
		}
	})

	t.Run("asking again keeps a requester suppressed", func(t *testing.T) {
		th := newRequestThrottle()
		th.canReplyNodeInfo(us, a)
		th.backdate(11 * time.Hour)
		th.canReplyNodeInfo(us, a) // suppressed, but restarts the window
		th.backdate(2 * time.Hour)
		if th.canReplyNodeInfo(us, a) {
			t.Error("a requester asking every 11 hours got a reply")
		}
	})

	t.Run("any NodeInfo sent starts the 30-minute floor", func(t *testing.T) {
		th := newRequestThrottle()
		th.noteNodeInfoSent(us) // a broadcast
		if th.canReplyNodeInfo(us, a) {
			t.Error("replied within 30 minutes of a broadcast")
		}
		th.backdate(31 * time.Minute)
		if !th.canReplyNodeInfo(us, b) {
			t.Error("refused after the floor passed")
		}
	})

	t.Run("each identity has its own limits", func(t *testing.T) {
		th := newRequestThrottle()
		th.noteNodeInfoSent(us)
		if !th.canReplyNodeInfo(core.NodeID(2), a) {
			t.Error("another identity's NodeInfo held this one back")
		}
	})

	t.Run("urgent sends use a one-minute floor", func(t *testing.T) {
		th := newRequestThrottle()
		th.noteNodeInfoSent(us)
		if th.canSendNodeInfoUrgently(us) {
			t.Error("urgent send within a minute")
		}
		th.backdate(2 * time.Minute)
		if !th.canSendNodeInfoUrgently(us) {
			t.Error("urgent send refused after a minute")
		}
	})
}

// A bridge broadcast of its NodeInfo starts the floor for its replies.
func TestBridgeNodeInfoSendStartsFloor(t *testing.T) {
	mt := newMockTransport()
	b := newTestBridge(t, mt)
	b.handleIncomingPacket(decodedPacket(0xAA, b.cfg.NodeID, 1, nodeInfoRequest()))
	if mt.sentCount() != 1 {
		t.Fatalf("sent %d replies to the first request, want 1", mt.sentCount())
	}
	b.handleIncomingPacket(decodedPacket(0xBB, b.cfg.NodeID, 2, nodeInfoRequest()))
	if mt.sentCount() != 1 {
		t.Error("replied to a second requester within 30 minutes of the last NodeInfo")
	}
}
