package client

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

// fakeDevice answers want_config with one node and config_complete_id, and
// forwards every other ToRadio it reads.
type fakeDevice struct {
	conn  *stream.Conn
	out   chan *pb.FromRadio
	other chan *pb.ToRadio
	wants chan uint32
}

func newFakeDevice(t *testing.T) (*fakeDevice, *Transport) {
	t.Helper()
	deviceSide, clientSide := net.Pipe()
	d := &fakeDevice{
		conn:  stream.NewRadioConn(deviceSide),
		out:   make(chan *pb.FromRadio, 16),
		other: make(chan *pb.ToRadio, 16),
		wants: make(chan uint32, 4),
	}
	// One writer keeps replies in order, as a real device sends them, without
	// blocking the reader while the client is busy writing.
	go func() {
		for msg := range d.out {
			if err := d.conn.Write(msg); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			msg := &pb.ToRadio{}
			if err := d.conn.Read(msg); err != nil {
				return
			}
			if id, ok := msg.PayloadVariant.(*pb.ToRadio_WantConfigId); ok {
				d.wants <- id.WantConfigId
				d.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_NodeInfo{NodeInfo: &pb.NodeInfo{Num: 0xAA}}})
				d.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_ConfigCompleteId{ConfigCompleteId: id.WantConfigId}})
				continue
			}
			d.other <- msg
		}
	}()
	tr := NewTransport(stream.NewRadioConn(clientSide), TransportConfig{})
	t.Cleanup(func() {
		tr.Stop()
		deviceSide.Close()
	})
	return d, tr
}

func (d *fakeDevice) send(msg *pb.FromRadio) {
	d.out <- msg
}

func connect(t *testing.T, tr *Transport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tr.Connect(ctx); err != nil {
		t.Fatal(err)
	}
}

// Firmware drops an API client after 15 minutes without a ToRadio, so an idle
// client has to send heartbeats.
func TestHeartbeat(t *testing.T) {
	d, tr := newFakeDevice(t)
	tr.heartbeatInterval = 10 * time.Millisecond
	connect(t, tr)

	select {
	case msg := <-d.other:
		if msg.GetHeartbeat() == nil {
			t.Errorf("got %v, want a heartbeat", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("no heartbeat sent")
	}
}

// After a reboot the device sends nothing until asked for its config again.
func TestRebootedRequestsConfigAgain(t *testing.T) {
	d, tr := newFakeDevice(t)
	connect(t, tr)
	first := <-d.wants

	d.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Rebooted{Rebooted: true}})
	select {
	case second := <-d.wants:
		if second == first {
			t.Error("reused the previous config id")
		}
	case <-time.After(time.Second):
		t.Fatal("no want_config after the device rebooted")
	}

	deadline := time.Now().Add(time.Second)
	for !tr.State().Complete() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !tr.State().Complete() {
		t.Fatal("handshake did not complete again")
	}
	if n := len(tr.State().Nodes()); n != 1 {
		t.Errorf("state has %d nodes after the second handshake, want 1", n)
	}
}

// Variants without handshake state, like firmware's client notifications, still
// reach handlers.
func TestNewerVariantsReachHandlers(t *testing.T) {
	d, tr := newFakeDevice(t)
	got := make(chan *pb.ClientNotification, 1)
	tr.Handle(&pb.ClientNotification{}, func(msg proto.Message) error {
		got <- msg.(*pb.ClientNotification)
		return nil
	})
	connect(t, tr)

	d.send(&pb.FromRadio{PayloadVariant: &pb.FromRadio_ClientNotification{ClientNotification: &pb.ClientNotification{Message: "duty cycle limit"}}})
	select {
	case n := <-got:
		if n.Message != "duty cycle limit" {
			t.Errorf("message %q", n.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("ClientNotification was not dispatched")
	}
}
