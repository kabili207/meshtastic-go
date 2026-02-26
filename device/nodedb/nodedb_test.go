package nodedb

import (
	"testing"

	"github.com/kabili207/meshtastic-go/core"
	"github.com/kabili207/meshtastic-go/core/crypto"
	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

func newTestDB() *NodeDB {
	return New(Config{
		SelfNode:  core.NodeID(0x12345678),
		LongName:  "Test Node",
		ShortName: "TST",
	})
}

func TestUpdate_NewNode(t *testing.T) {
	db := newTestDB()
	db.Update(0xAABBCCDD, func(info *pb.NodeInfo) {
		info.User = &pb.User{LongName: "Remote Node"}
	})

	got := db.Get(0xAABBCCDD)
	if got == nil {
		t.Fatal("expected node to exist")
	}
	if got.User.LongName != "Remote Node" {
		t.Errorf("got LongName %q, want %q", got.User.LongName, "Remote Node")
	}
	if got.LastHeard == 0 {
		t.Error("expected LastHeard to be set")
	}
}

func TestUpdate_ExistingNode(t *testing.T) {
	db := newTestDB()
	db.Update(0x11, func(info *pb.NodeInfo) {
		info.User = &pb.User{LongName: "First"}
	})
	db.Update(0x11, func(info *pb.NodeInfo) {
		info.User.ShortName = "F"
	})

	got := db.Get(0x11)
	if got.User.LongName != "First" {
		t.Errorf("got LongName %q, want %q", got.User.LongName, "First")
	}
	if got.User.ShortName != "F" {
		t.Errorf("got ShortName %q, want %q", got.User.ShortName, "F")
	}
}

func TestGet_NotFound(t *testing.T) {
	db := newTestDB()
	if got := db.Get(0x99); got != nil {
		t.Errorf("expected nil for unknown node, got %v", got)
	}
}

func TestGet_ReturnsClone(t *testing.T) {
	db := newTestDB()
	db.Update(0x11, func(info *pb.NodeInfo) {
		info.User = &pb.User{LongName: "Original"}
	})

	got := db.Get(0x11)
	got.User.LongName = "Mutated"

	original := db.Get(0x11)
	if original.User.LongName != "Original" {
		t.Error("Get returned a reference instead of a clone")
	}
}

func TestAll_ReturnsClones(t *testing.T) {
	db := newTestDB()
	db.Update(0x11, func(info *pb.NodeInfo) {
		info.User = &pb.User{LongName: "Node1"}
	})
	db.Update(0x22, func(info *pb.NodeInfo) {
		info.User = &pb.User{LongName: "Node2"}
	})

	all := db.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(all))
	}

	// Mutate returned slice
	all[0].User.LongName = "Mutated"

	// Verify original is untouched
	fresh := db.All()
	for _, n := range fresh {
		if n.User.LongName == "Mutated" {
			t.Error("All returned references instead of clones")
		}
	}
}

func TestSelfInfo(t *testing.T) {
	db := newTestDB()
	self := db.SelfInfo()
	if self.Num != 0x12345678 {
		t.Errorf("got Num %x, want %x", self.Num, 0x12345678)
	}
	if self.User.LongName != "Test Node" {
		t.Errorf("got LongName %q, want %q", self.User.LongName, "Test Node")
	}
}

func TestProcessPacket_NodeInfo(t *testing.T) {
	db := newTestDB()

	user := &pb.User{LongName: "Discovered", ShortName: "DSC"}
	userBytes, _ := proto.Marshal(user)
	data := &pb.Data{
		Portnum: pb.PortNum_NODEINFO_APP,
		Payload: userBytes,
	}
	dataBytes, _ := proto.Marshal(data)

	// Encrypt with default key
	encrypted, _ := crypto.XOR(dataBytes, crypto.DefaultKey, 42, 0xAA)

	pkt := &pb.MeshPacket{
		Id:   42,
		From: 0xAA,
		PayloadVariant: &pb.MeshPacket_Encrypted{
			Encrypted: encrypted,
		},
	}

	updated := db.ProcessPacket(pkt, crypto.DefaultKey)
	if !updated {
		t.Fatal("expected ProcessPacket to return true")
	}

	got := db.Get(0xAA)
	if got == nil {
		t.Fatal("expected node to exist after ProcessPacket")
	}
	if got.User.LongName != "Discovered" {
		t.Errorf("got LongName %q, want %q", got.User.LongName, "Discovered")
	}
}

func TestProcessPacket_Decoded(t *testing.T) {
	db := newTestDB()

	user := &pb.User{LongName: "Plaintext"}
	userBytes, _ := proto.Marshal(user)

	pkt := &pb.MeshPacket{
		Id:   1,
		From: 0xBB,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_NODEINFO_APP,
				Payload: userBytes,
			},
		},
	}

	updated := db.ProcessPacket(pkt, nil)
	if !updated {
		t.Fatal("expected ProcessPacket to return true")
	}

	got := db.Get(0xBB)
	if got.User.LongName != "Plaintext" {
		t.Errorf("got LongName %q, want %q", got.User.LongName, "Plaintext")
	}
}

func TestProcessPacket_UnknownPortNum(t *testing.T) {
	db := newTestDB()

	payload, _ := proto.Marshal(&pb.Data{
		Portnum: pb.PortNum_TEXT_MESSAGE_APP,
		Payload: []byte("hello"),
	})

	pkt := &pb.MeshPacket{
		Id:   1,
		From: 0xCC,
		PayloadVariant: &pb.MeshPacket_Decoded{
			Decoded: &pb.Data{
				Portnum: pb.PortNum_TEXT_MESSAGE_APP,
				Payload: payload,
			},
		},
	}

	updated := db.ProcessPacket(pkt, nil)
	if updated {
		t.Error("expected ProcessPacket to return false for TEXT_MESSAGE_APP")
	}
}
