package lora

import (
	"slices"
	"testing"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Expected output was produced by compiling firmware's own region table and the
// getRegionPresetMap loop from src/mesh/RadioInterface.cpp at v2.8.0.47db0e3,
// then printing the result. Values are the raw enum numbers so the fixture
// matches the C output line for line.
var (
	expectedGroups = []struct {
		def     int32
		lic     bool
		presets []int32
	}{
		{0, false, []int32{0, 1, 3, 4, 5, 6, 7, 8, 9, 16}},
		{0, false, []int32{0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13}},
		{10, false, []int32{0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13}},
		{13, false, []int32{0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13}},
		{14, true, []int32{14, 15}},
		{13, true, []int32{12, 13}},
	}
	expectedRegionGroups = [][2]int32{
		{1, 0}, {2, 0}, {3, 1}, {29, 2}, {32, 3}, {4, 0}, {5, 0}, {6, 0}, {22, 0}, {9, 0},
		{7, 0}, {8, 0}, {10, 0}, {11, 0}, {12, 0}, {14, 0}, {16, 0}, {17, 0}, {18, 0}, {19, 0},
		{20, 0}, {21, 0}, {23, 0}, {24, 0}, {25, 0}, {26, 0}, {27, 4}, {28, 4}, {33, 4}, {37, 5},
		{34, 5}, {35, 5}, {36, 5}, {13, 0},
	}
)

func TestRegionPresetMapMatchesFirmware(t *testing.T) {
	m := RegionPresetMap()

	if len(m.Groups) != len(expectedGroups) {
		t.Fatalf("got %d groups, want %d", len(m.Groups), len(expectedGroups))
	}
	for i, want := range expectedGroups {
		got := m.Groups[i]
		if int32(got.DefaultPreset) != want.def || got.LicensedOnly != want.lic {
			t.Errorf("group %d: default=%d licensed=%v, want default=%d licensed=%v",
				i, got.DefaultPreset, got.LicensedOnly, want.def, want.lic)
		}
		presets := make([]int32, len(got.Presets))
		for j, p := range got.Presets {
			presets[j] = int32(p)
		}
		if !slices.Equal(presets, want.presets) {
			t.Errorf("group %d: presets %v, want %v", i, presets, want.presets)
		}
	}

	if len(m.RegionGroups) != len(expectedRegionGroups) {
		t.Fatalf("got %d region mappings, want %d", len(m.RegionGroups), len(expectedRegionGroups))
	}
	for i, want := range expectedRegionGroups {
		got := m.RegionGroups[i]
		if int32(got.Region) != want[0] || int32(got.GroupIndex) != want[1] {
			t.Errorf("mapping %d: region %d -> group %d, want region %d -> group %d",
				i, got.Region, got.GroupIndex, want[0], want[1])
		}
	}
}

func TestRegionPresetMapInvariants(t *testing.T) {
	m := RegionPresetMap()

	if len(m.Groups) > maxPresetGroups || len(m.RegionGroups) > maxRegionGroups {
		t.Errorf("map exceeds wire caps: %d groups, %d regions", len(m.Groups), len(m.RegionGroups))
	}
	seen := map[pb.Config_LoRaConfig_RegionCode]bool{}
	for _, rg := range m.RegionGroups {
		if int(rg.GroupIndex) >= len(m.Groups) {
			t.Errorf("region %v points at group %d of %d", rg.Region, rg.GroupIndex, len(m.Groups))
		}
		if seen[rg.Region] {
			t.Errorf("region %v mapped twice", rg.Region)
		}
		seen[rg.Region] = true
	}
	for _, g := range m.Groups {
		if len(g.Presets) > maxGroupPresets {
			t.Errorf("group has %d presets, cap is %d", len(g.Presets), maxGroupPresets)
		}
		if !slices.Contains(g.Presets, g.DefaultPreset) {
			t.Errorf("default preset %v is not in its own group's list", g.DefaultPreset)
		}
	}

	// A region with no entry is unconstrained by definition. UNSET is the table's
	// terminator, and UA_868 is deprecated with no table entry at all.
	for _, absent := range []pb.Config_LoRaConfig_RegionCode{pb.Config_LoRaConfig_UNSET, pb.Config_LoRaConfig_UA_868} {
		if seen[absent] {
			t.Errorf("%v should have no entry", absent)
		}
	}

	// Licensing must survive grouping: the ham profiles share preset lists with
	// unlicensed ones and would be merged away if grouping keyed on the list.
	var licensed, unlicensedNarrow int
	for _, g := range m.Groups {
		if g.LicensedOnly {
			licensed++
		}
		if !g.LicensedOnly && slices.Equal(g.Presets, presetsNarrow) {
			unlicensedNarrow++
		}
	}
	if licensed != 2 {
		t.Errorf("got %d licensed groups, want 2 (2 m and 70 cm ham profiles)", licensed)
	}
	if unlicensedNarrow != 0 {
		t.Error("an unlicensed group carries the bare narrow list; EU_N_868 must advertise the EU superset instead")
	}
}

func TestRegionPresetMapReturnsFreshMessages(t *testing.T) {
	a, b := RegionPresetMap(), RegionPresetMap()
	if a == b {
		t.Fatal("same pointer returned twice")
	}
	a.Groups[0].Presets[0] = pb.Config_LoRaConfig_VERY_LONG_SLOW
	if b.Groups[0].Presets[0] == pb.Config_LoRaConfig_VERY_LONG_SLOW {
		t.Error("mutating one map's presets altered another's")
	}
}
