package clientapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kabili207/meshtastic-go/core"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"github.com/kabili207/meshtastic-go/transport/stream"
	"google.golang.org/protobuf/proto"
)

// admin sends a local admin request asking for a response and returns what came
// back: an AdminMessage reply, or else the Routing result.
func admin(t *testing.T, conn *stream.Conn, id uint32, req *pb.AdminMessage) (*pb.AdminMessage, pb.Routing_Error) {
	t.Helper()
	payload, _ := proto.Marshal(req)
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_Packet{Packet: &pb.MeshPacket{
		Id: id, To: selfID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_ADMIN_APP, Payload: payload, WantResponse: true}},
	}}})
	data := readWithin(t, conn, time.Second).GetPacket().GetDecoded()
	if data == nil || data.RequestId != id {
		t.Fatalf("reply %v, want one for request %d", data, id)
	}
	switch data.Portnum {
	case pb.PortNum_ADMIN_APP:
		reply := &pb.AdminMessage{}
		if err := proto.Unmarshal(data.Payload, reply); err != nil {
			t.Fatal(err)
		}
		return reply, pb.Routing_NONE
	case pb.PortNum_ROUTING_APP:
		r := &pb.Routing{}
		if err := proto.Unmarshal(data.Payload, r); err != nil {
			t.Fatal(err)
		}
		return nil, r.GetErrorReason()
	}
	t.Fatalf("reply on %v", data.Portnum)
	return nil, 0
}

func TestAdminReads(t *testing.T) {
	conn := connect(t, testServer(t))

	owner, _ := admin(t, conn, 1, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetOwnerRequest{GetOwnerRequest: true}})
	if owner.GetGetOwnerResponse().GetId() != selfID.String() || len(owner.GetSessionPasskey()) != 8 {
		t.Errorf("owner reply %v, want our user and an 8-byte session passkey", owner)
	}

	// get_channel_request carries the index plus one.
	ch, _ := admin(t, conn, 2, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetChannelRequest{GetChannelRequest: 1}})
	if c := ch.GetGetChannelResponse(); c.GetIndex() != 0 || c.GetSettings().GetName() != "LongFast" {
		t.Errorf("channel reply %v, want the primary", c)
	}
	if _, reason := admin(t, conn, 3, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetChannelRequest{GetChannelRequest: 0}}); reason != pb.Routing_BAD_REQUEST {
		t.Errorf("channel 0 (index -1): %v, want BAD_REQUEST", reason)
	}

	cfg, _ := admin(t, conn, 4, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetConfigRequest{GetConfigRequest: pb.AdminMessage_LORA_CONFIG}})
	if cfg.GetGetConfigResponse().GetLora().GetRegion() != pb.Config_LoRaConfig_US {
		t.Errorf("LoRa config reply %v", cfg)
	}
	mod, _ := admin(t, conn, 5, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetModuleConfigRequest{GetModuleConfigRequest: pb.AdminMessage_MESHBEACON_CONFIG}})
	if mod.GetGetModuleConfigResponse().GetMeshBeacon() == nil {
		t.Errorf("mesh beacon config reply %v", mod)
	}
}

func TestAdminWritesNeedAHandler(t *testing.T) {
	conn := connect(t, testServer(t))
	_, reason := admin(t, conn, 1, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_SetOwner{SetOwner: &pb.User{LongName: "Renamed"}}})
	if reason != pb.Routing_NOT_AUTHORIZED {
		t.Errorf("set_owner without a handler: %v, want NOT_AUTHORIZED", reason)
	}
}

func TestAdminWritesThroughHandler(t *testing.T) {
	var seen []*pb.AdminMessage
	refuse := false
	s := testServer(t, func(c *Config) {
		c.OnConfigChange = func(change *pb.AdminMessage) error {
			seen = append(seen, change)
			if refuse {
				return errors.New("no")
			}
			return nil
		}
	})
	conn := connect(t, s)

	if _, reason := admin(t, conn, 1, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_SetOwner{SetOwner: &pb.User{LongName: "Renamed"}}}); reason != pb.Routing_NONE {
		t.Fatalf("accepted set_owner: %v", reason)
	}
	owner, _ := admin(t, conn, 2, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetOwnerRequest{GetOwnerRequest: true}})
	if u := owner.GetGetOwnerResponse(); u.GetLongName() != "Renamed" || u.GetId() != selfID.String() {
		t.Errorf("owner after set: %v, want the new name with our own id", u)
	}

	// An app may send a private key; it is kept from every reply all the same.
	key := &pb.Config{PayloadVariant: &pb.Config_Security{Security: &pb.Config_SecurityConfig{PrivateKey: make([]byte, 32)}}}
	admin(t, conn, 3, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_SetConfig{SetConfig: key}})
	sec, _ := admin(t, conn, 4, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetConfigRequest{GetConfigRequest: pb.AdminMessage_SECURITY_CONFIG}})
	if len(sec.GetGetConfigResponse().GetSecurity().GetPrivateKey()) != 0 {
		t.Error("a private key was sent to the client")
	}

	refuse = true
	if _, reason := admin(t, conn, 5, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_SetOwner{SetOwner: &pb.User{LongName: "Refused"}}}); reason != pb.Routing_BAD_REQUEST {
		t.Errorf("refused set_owner: %v, want BAD_REQUEST", reason)
	}
	owner, _ = admin(t, conn, 6, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetOwnerRequest{GetOwnerRequest: true}})
	if owner.GetGetOwnerResponse().GetLongName() != "Renamed" {
		t.Error("a refused change was applied")
	}
	if len(seen) != 3 {
		t.Errorf("handler saw %d changes, want 3", len(seen))
	}
}

func TestAdminActionsRefused(t *testing.T) {
	conn := connect(t, testServer(t))
	if _, reason := admin(t, conn, 1, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_RebootSeconds{RebootSeconds: 5}}); reason != pb.Routing_NOT_AUTHORIZED {
		t.Errorf("reboot: %v, want NOT_AUTHORIZED", reason)
	}
	if _, reason := admin(t, conn, 2, &pb.AdminMessage{PayloadVariant: &pb.AdminMessage_BeginEditSettings{BeginEditSettings: true}}); reason != pb.Routing_NONE {
		t.Errorf("begin_edit_settings: %v, want an ack", reason)
	}
}

// Admin for another node goes to the mesh, as firmware forwards it.
func TestRemoteAdminForwarded(t *testing.T) {
	var forwarded *pb.MeshPacket
	conn := connect(t, testServer(t, func(c *Config) {
		c.OnOutboundPacket = func(_ context.Context, pkt *pb.MeshPacket) pb.Routing_Error {
			forwarded = pkt
			return pb.Routing_NONE
		}
	}))
	payload, _ := proto.Marshal(&pb.AdminMessage{PayloadVariant: &pb.AdminMessage_GetOwnerRequest{GetOwnerRequest: true}})
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_Packet{Packet: &pb.MeshPacket{
		Id: 9, To: core.NodeID(0xAA).Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_ADMIN_APP, Payload: payload, WantResponse: true}},
	}}})
	if qs := readWithin(t, conn, time.Second).GetQueueStatus(); qs.GetMeshPacketId() != 9 {
		t.Fatalf("got %v, want a QueueStatus for the forwarded packet", qs)
	}
	if forwarded == nil || forwarded.To != 0xAA {
		t.Errorf("forwarded %v, want the admin request to !000000aa", forwarded)
	}
}

func TestMalformedAdminKeepsConnection(t *testing.T) {
	conn := connect(t, testServer(t))
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_Packet{Packet: &pb.MeshPacket{
		Id: 1, To: selfID.Uint32(),
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_ADMIN_APP, Payload: []byte{0xFF, 0xFF}}},
	}}})
	send(t, conn, &pb.ToRadio{PayloadVariant: &pb.ToRadio_Heartbeat{Heartbeat: &pb.Heartbeat{}}})
	if readWithin(t, conn, time.Second).GetQueueStatus() == nil {
		t.Error("connection did not survive a malformed admin message")
	}
}
