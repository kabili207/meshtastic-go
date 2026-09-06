package raw

import (
	"context"
	"testing"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport"
)

// fakeTransport is a RawTransport whose connection state and emitted events are
// driven by the test.
type fakeTransport struct {
	connected bool
	state     transport.StateHandler
}

func (f *fakeTransport) Start(context.Context) error               { return nil }
func (f *fakeTransport) Stop() error                               { return nil }
func (f *fakeTransport) IsConnected() bool                         { return f.connected }
func (f *fakeTransport) SetPacketHandler(transport.PacketHandler)  {}
func (f *fakeTransport) SetStateHandler(fn transport.StateHandler) { f.state = fn }
func (f *fakeTransport) SendPacket(string, *pb.MeshPacket) error   { return nil }
func (f *fakeTransport) AddChannel(string)                         {}
func (f *fakeTransport) emit(e transport.ListenerEvent)            { f.state(f, e) }

func newMultiWithFakes() (*MultiTransport, *fakeTransport, *fakeTransport, *[]transport.ListenerEvent) {
	a, b := &fakeTransport{}, &fakeTransport{}
	m := NewMultiTransport(MultiConfig{}, TransportOption{Transport: a}, TransportOption{Transport: b})
	var got []transport.ListenerEvent
	m.SetStateHandler(func(_ transport.Transport, e transport.ListenerEvent) {
		got = append(got, e)
	})
	return m, a, b, &got
}

// A child that is itself still marked connected (the UDP transport rebinds before it
// reports) must not suppress its own Reconnecting when no other child is up.
func TestReconnectingIgnoresEmittingChildState(t *testing.T) {
	_, a, _, got := newMultiWithFakes()
	a.connected = true
	a.emit(transport.ListenerEventReconnecting)
	if len(*got) != 1 || (*got)[0] != transport.ListenerEventReconnecting {
		t.Fatalf("events = %v, want [reconnecting]", *got)
	}
}

func TestReconnectingSuppressedWhileAnotherChildConnected(t *testing.T) {
	_, a, b, got := newMultiWithFakes()
	a.connected = true
	b.emit(transport.ListenerEventReconnecting)
	if len(*got) != 0 {
		t.Fatalf("events = %v, want none", *got)
	}
}

func TestDisconnectedOnlyWhenAllChildrenDown(t *testing.T) {
	_, a, b, got := newMultiWithFakes()
	a.connected = true
	b.emit(transport.ListenerEventDisconnected)
	if len(*got) != 0 {
		t.Fatalf("events = %v, want none while a is connected", *got)
	}
	a.connected = false
	a.emit(transport.ListenerEventDisconnected)
	if len(*got) != 1 || (*got)[0] != transport.ListenerEventDisconnected {
		t.Fatalf("events = %v, want [disconnected]", *got)
	}
}
