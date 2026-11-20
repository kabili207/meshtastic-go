package clientapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport/stream"
)

const selfID = core.NodeID(0x12345678)

type fakeNodes struct{ others []*pb.NodeInfo }

func (f fakeNodes) SelfInfo() *pb.NodeInfo {
	return &pb.NodeInfo{Num: selfID.Uint32(), User: &pb.User{Id: selfID.String(), LongName: "Go Node"}}
}
func (f fakeNodes) All() []*pb.NodeInfo                    { return f.others }
func (f fakeNodes) Channel(uint32) (core.ChannelDef, bool) { return nil, false }

func testServer(t *testing.T, opts ...func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		NodeID:    selfID,
		HwModel:   pb.HardwareModel_PRIVATE_HW,
		PublicKey: make([]byte, 32),
		Channels:  &pb.ChannelSet{Settings: []*pb.ChannelSettings{{Name: "LongFast", Psk: crypto.DefaultKey}}},
		LoRa:      &pb.Config_LoRaConfig{UsePreset: true, Region: pb.Config_LoRaConfig_US},
		Nodes: fakeNodes{others: []*pb.NodeInfo{
			{Num: 0xAA, User: &pb.User{Id: "wrong", LongName: "Peer"}},
		}},
		NextPacketID: func() uint32 { return 1 },
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return New(cfg)
}

func connect(t *testing.T, s *Server) *stream.Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn := stream.NewRadioConn(s.Conn(ctx))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func send(t *testing.T, conn *stream.Conn, msg *pb.ToRadio) {
	t.Helper()
	if err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
}

// handshake runs a want_config and returns every frame up to config_complete_id.
func handshake(t *testing.T, conn *stream.Conn, nonce uint32) []*pb.FromRadio {
	t.Helper()
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_WantConfigId{WantConfigId: nonce}})
	var frames []*pb.FromRadio
	for {
		fr := &pb.FromRadio{}
		if err := conn.Read(fr); err != nil {
			t.Fatalf("reading handshake after %d frames: %v", len(frames), err)
		}
		frames = append(frames, fr)
		if id, ok := fr.PayloadVariant.(*pb.FromRadio_ConfigCompleteId); ok {
			if id.ConfigCompleteId != nonce {
				t.Errorf("config_complete_id %d, want %d", id.ConfigCompleteId, nonce)
			}
			return frames
		}
	}
}

// kinds names each frame, collapsing runs of the same kind.
func kinds(frames []*pb.FromRadio) []string {
	var out []string
	for _, f := range frames {
		k := fmt.Sprintf("%T", f.PayloadVariant)[len("*proto.FromRadio_"):]
		if len(out) == 0 || out[len(out)-1] != k {
			out = append(out, k)
		}
	}
	return out
}

// Firmware's PhoneAPI sequence, which client apps assume.
func TestHandshakeOrder(t *testing.T) {
	frames := handshake(t, connect(t, testServer(t)), 7)
	want := []string{"MyInfo", "DeviceuiConfig", "NodeInfo", "Metadata", "RegionPresets",
		"Channel", "Config", "ModuleConfig", "NodeInfo", "ConfigCompleteId"}
	if got := kinds(frames); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("handshake order\n got %v\nwant %v", got, want)
	}

	var configs []*pb.Config
	modules := 0
	for _, f := range frames {
		switch v := f.PayloadVariant.(type) {
		case *pb.FromRadio_Config:
			configs = append(configs, v.Config)
		case *pb.FromRadio_ModuleConfig:
			modules++
		}
	}
	// Every Config variant (device through device_ui) and ModuleConfig variant
	// (mqtt through mesh_beacon), as firmware's handshake loops send them.
	if len(configs) != 10 || modules != 17 {
		t.Errorf("%d config and %d module config frames, want every section: 10 and 17", len(configs), modules)
	}
	for _, c := range configs {
		if lora := c.GetLora(); lora != nil && lora.Region != pb.Config_LoRaConfig_US {
			t.Errorf("LoRa region %v, want the configured US", lora.Region)
		}
		if sec := c.GetSecurity(); sec != nil && (len(sec.PublicKey) != 32 || len(sec.PrivateKey) != 0) {
			t.Errorf("security config: public %d bytes, private %d; want the public key only", len(sec.PublicKey), len(sec.PrivateKey))
		}
	}
}

func TestHandshakeContents(t *testing.T) {
	frames := handshake(t, connect(t, testServer(t)), 7)
	var nodes []*pb.NodeInfo
	for _, f := range frames {
		switch v := f.PayloadVariant.(type) {
		case *pb.FromRadio_Metadata:
			m := v.Metadata
			if m.FirmwareVersion != FirmwareVersion || m.DeviceStateVersion != deviceStateVersion || !m.HasPKC {
				t.Errorf("metadata %v", m)
			}
			if m.ExcludedModules != excludedModules {
				t.Errorf("excluded modules %#x, want %#x", m.ExcludedModules, excludedModules)
			}
		case *pb.FromRadio_NodeInfo:
			nodes = append(nodes, v.NodeInfo)
		}
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d NodeInfos, want own and one other", len(nodes))
	}
	if own := nodes[0]; own.Num != selfID.Uint32() || !own.IsFavorite || len(own.User.PublicKey) != 32 {
		t.Errorf("own NodeInfo %v, want ours, a favorite, with our key", own)
	}
	if id := nodes[1].User.Id; id != "!000000aa" {
		t.Errorf("other node's user id %q, want it derived from its number", id)
	}
}

// The special nonces trim the handshake: 69420 sends config without other nodes,
// 69421 the node database without config.
func TestHandshakeSpecialNonces(t *testing.T) {
	onlyConfig := kinds(handshake(t, connect(t, testServer(t)), nonceOnlyConfig))
	if want := "[MyInfo DeviceuiConfig NodeInfo Metadata RegionPresets Channel Config ModuleConfig ConfigCompleteId]"; fmt.Sprint(onlyConfig) != want {
		t.Errorf("config only: %v", onlyConfig)
	}
	onlyNodes := kinds(handshake(t, connect(t, testServer(t)), nonceOnlyNodes))
	if want := "[MyInfo DeviceuiConfig NodeInfo ConfigCompleteId]"; fmt.Sprint(onlyNodes) != want {
		t.Errorf("nodes only: %v", onlyNodes)
	}
}

// Like firmware, live packets wait until the handshake has finished.
func TestPacketsHeldUntilHandshake(t *testing.T) {
	s := testServer(t)
	conn := connect(t, s)
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	s.DispatchToClients(&pb.FromRadio{PayloadVariant: &pb.FromRadio_Packet{Packet: &pb.MeshPacket{Id: 99}}})

	frames := handshake(t, conn, 7)
	if frames[0].GetPacket() != nil {
		t.Fatal("a live packet was sent before the handshake")
	}
	if fr := readWithin(t, conn, time.Second); fr.GetPacket().GetId() != 99 {
		t.Errorf("after the handshake got %v, want the held packet", fr)
	}
}

func readWithin(t *testing.T, conn *stream.Conn, d time.Duration) *pb.FromRadio {
	t.Helper()
	got := make(chan *pb.FromRadio, 1)
	go func() {
		fr := &pb.FromRadio{}
		if conn.Read(fr) == nil {
			got <- fr
		}
	}()
	select {
	case fr := <-got:
		return fr
	case <-time.After(d):
		t.Fatal("no frame received")
		return nil
	}
}

func TestHeartbeatGetsQueueStatus(t *testing.T) {
	conn := connect(t, testServer(t))
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_Heartbeat{Heartbeat: &pb.Heartbeat{}}})
	fr := &pb.FromRadio{}
	if err := conn.Read(fr); err != nil || fr.GetQueueStatus() == nil {
		t.Errorf("got %v, %v; want a QueueStatus", fr, err)
	}
}

func TestDisconnectClosesConnection(t *testing.T) {
	conn := connect(t, testServer(t))
	handshake(t, conn, 7)
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_Disconnect{Disconnect: true}})
	done := make(chan error, 1)
	go func() { done <- conn.Read(&pb.FromRadio{}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("read a frame after disconnecting")
		}
	case <-time.After(time.Second):
		t.Error("connection still open after disconnect")
	}
}
