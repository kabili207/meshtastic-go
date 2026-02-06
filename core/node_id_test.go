package core

import (
	"bytes"
	"testing"
)

const testNodeID = 3735928559

func TestNodeID_Uint32(t *testing.T) {
	nodeID := NodeID(testNodeID)
	got := nodeID.Uint32()
	if got != testNodeID {
		t.Errorf("expected %v, got %v", testNodeID, got)
	}
}

func TestNodeID_Bytes(t *testing.T) {
	nodeID := NodeID(testNodeID)
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	got := nodeID.Bytes()
	if !bytes.Equal(got, want) {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestNodeID_String(t *testing.T) {
	nodeID := NodeID(testNodeID)
	want := "!deadbeef"
	got := nodeID.String()
	if want != got {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestNodeID_DefaultShortName(t *testing.T) {
	nodeID := NodeID(testNodeID)
	want := "beef"
	got := nodeID.DefaultShortName()
	if want != got {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestNodeID_DefaultLongName(t *testing.T) {
	nodeID := NodeID(testNodeID)
	want := "Meshtastic beef"
	got := nodeID.DefaultLongName()
	if want != got {
		t.Errorf("expected %v, got %v", want, got)
	}
}

// TestRandomNodeID ensures that RandomNodeID generates a valid NodeID and that multiple calls generate different
// NodeIDs.
func TestRandomNodeID(t *testing.T) {
	nodeID1, err := RandomNodeID()
	if err != nil {
		t.Errorf("expected no error when generating the first node id, got %v", err)
	}
	t.Logf("nodeID1: %s", nodeID1)
	nodeID2, err := RandomNodeID()
	if err != nil {
		t.Errorf("expected no error when generating the second node id, got %v", err)
	}
	t.Logf("nodeID2: %s", nodeID2)
	if nodeID1 == nodeID2 {
		t.Errorf("expected random node ids to be different, got %s and %s", nodeID1, nodeID2)
	}
}

func TestParseNodeID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    NodeID
		wantErr bool
	}{
		{"meshtastic format", "!deadbeef", NodeID(0xdeadbeef), false},
		{"hex with 0x", "0xdeadbeef", NodeID(0xdeadbeef), false},
		{"hex with 0X", "0XDEADBEEF", NodeID(0xdeadbeef), false},
		{"plain hex", "deadbeef", NodeID(0xdeadbeef), false},
		{"decimal", "12345", NodeID(12345), false},
		{"8 char with hex digit", "1234567a", NodeID(0x1234567a), false},
		{"empty", "", 0, true},
		{"invalid", "zzz", 0, true},
		{"whitespace trimmed", "  !deadbeef  ", NodeID(0xdeadbeef), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNodeID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseNodeID(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseNodeID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNodeID_UnmarshalText(t *testing.T) {
	var n NodeID
	err := n.UnmarshalText([]byte("!deadbeef"))
	if err != nil {
		t.Errorf("UnmarshalText error: %v", err)
	}
	if n != NodeID(0xdeadbeef) {
		t.Errorf("UnmarshalText got %v, want %v", n, NodeID(0xdeadbeef))
	}
}

func TestNodeID_MarshalText(t *testing.T) {
	n := NodeID(0xdeadbeef)
	got, err := n.MarshalText()
	if err != nil {
		t.Errorf("MarshalText error: %v", err)
	}
	if string(got) != "!deadbeef" {
		t.Errorf("MarshalText got %q, want %q", string(got), "!deadbeef")
	}
}

func TestNodeID_IsReservedID(t *testing.T) {
	tests := []struct {
		nodeID NodeID
		want   bool
	}{
		{NodeID(0), true},          // Reserved
		{NodeID(3), true},          // Reserved
		{NodeID(4), false},         // First valid
		{NodeID(12345), false},     // Normal
		{BroadcastNodeID, true},    // Broadcast
		{BroadcastNodeIDNoLora, true}, // No-LoRa broadcast
	}

	for _, tt := range tests {
		t.Run(tt.nodeID.String(), func(t *testing.T) {
			if got := tt.nodeID.IsReservedID(); got != tt.want {
				t.Errorf("IsReservedID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeID_IsBroadcast(t *testing.T) {
	tests := []struct {
		nodeID NodeID
		want   bool
	}{
		{NodeID(12345), false},
		{BroadcastNodeID, true},
		{BroadcastNodeIDNoLora, true},
	}

	for _, tt := range tests {
		t.Run(tt.nodeID.String(), func(t *testing.T) {
			if got := tt.nodeID.IsBroadcast(); got != tt.want {
				t.Errorf("IsBroadcast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeID_GetNodeColor(t *testing.T) {
	n := NodeID(0xdeadbeef)
	color := n.GetNodeColor()
	// Should be a valid hex color
	if len(color) != 7 || color[0] != '#' {
		t.Errorf("GetNodeColor() = %q, want 7-char hex color", color)
	}

	// Same node should always get same color
	if color != n.GetNodeColor() {
		t.Errorf("GetNodeColor() not deterministic")
	}
}

func TestNodeID_ToMacAddress(t *testing.T) {
	n := NodeID(0xdeadbeef)
	mac := n.ToMacAddress()
	want := "02:00:de:ad:be:ef"
	if mac != want {
		t.Errorf("ToMacAddress() = %q, want %q", mac, want)
	}
}
