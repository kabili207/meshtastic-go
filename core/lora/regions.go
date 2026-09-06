package lora

import (
	"slices"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Which modem presets each LoRa region permits, as firmware advertises them to
// clients during the want_config handshake so a UI can refuse an illegal
// region-and-preset pairing. Transcribed from the region table in
// src/mesh/RadioInterface.cpp at v2.8.0.47db0e3 and cross-checked against it.

// Wire caps from mesh.options. Firmware truncates to these so the whole map fits
// one FromRadio; matching them keeps our map decodable by the same clients.
const (
	maxPresetGroups = 8
	maxRegionGroups = 38
	maxGroupPresets = 11
)

type regionProfile struct {
	presets      []pb.Config_LoRaConfig_ModemPreset
	licensedOnly bool
}

var (
	presetsStd = []pb.Config_LoRaConfig_ModemPreset{
		pb.Config_LoRaConfig_LONG_FAST, pb.Config_LoRaConfig_LONG_SLOW, pb.Config_LoRaConfig_MEDIUM_SLOW,
		pb.Config_LoRaConfig_MEDIUM_FAST, pb.Config_LoRaConfig_SHORT_SLOW, pb.Config_LoRaConfig_SHORT_FAST,
		pb.Config_LoRaConfig_LONG_MODERATE, pb.Config_LoRaConfig_SHORT_TURBO, pb.Config_LoRaConfig_LONG_TURBO,
		pb.Config_LoRaConfig_MEDIUM_TURBO,
	}
	presetsEU868 = []pb.Config_LoRaConfig_ModemPreset{
		pb.Config_LoRaConfig_LONG_FAST, pb.Config_LoRaConfig_LONG_SLOW, pb.Config_LoRaConfig_MEDIUM_SLOW,
		pb.Config_LoRaConfig_MEDIUM_FAST, pb.Config_LoRaConfig_SHORT_SLOW, pb.Config_LoRaConfig_SHORT_FAST,
		pb.Config_LoRaConfig_LONG_MODERATE,
	}
	presetsLite   = []pb.Config_LoRaConfig_ModemPreset{pb.Config_LoRaConfig_LITE_FAST, pb.Config_LoRaConfig_LITE_SLOW}
	presetsNarrow = []pb.Config_LoRaConfig_ModemPreset{pb.Config_LoRaConfig_NARROW_FAST, pb.Config_LoRaConfig_NARROW_SLOW}
	presetsTiny   = []pb.Config_LoRaConfig_ModemPreset{pb.Config_LoRaConfig_TINY_FAST, pb.Config_LoRaConfig_TINY_SLOW}

	// The EU_868, EU_866 and EU_N_868 trio own mutually exclusive preset lists, and
	// selecting a sibling's preset swaps the region to that sibling. So each of the
	// three advertises this union; on-device enforcement still uses its own list.
	presetsEUSuperset = []pb.Config_LoRaConfig_ModemPreset{
		pb.Config_LoRaConfig_LONG_FAST, pb.Config_LoRaConfig_LONG_SLOW, pb.Config_LoRaConfig_MEDIUM_SLOW,
		pb.Config_LoRaConfig_MEDIUM_FAST, pb.Config_LoRaConfig_SHORT_SLOW, pb.Config_LoRaConfig_SHORT_FAST,
		pb.Config_LoRaConfig_LONG_MODERATE, pb.Config_LoRaConfig_LITE_FAST, pb.Config_LoRaConfig_LITE_SLOW,
		pb.Config_LoRaConfig_NARROW_FAST, pb.Config_LoRaConfig_NARROW_SLOW,
	}

	profileStd    = &regionProfile{presets: presetsStd}
	profileEU868  = &regionProfile{presets: presetsEU868}
	profileLite   = &regionProfile{presets: presetsLite}
	profileNarrow = &regionProfile{presets: presetsNarrow}
	// Ham profiles share preset lists with unlicensed ones but are distinct
	// profiles: grouping keys on the profile, so licensing never gets merged away.
	profileHam20kHz  = &regionProfile{presets: presetsTiny, licensedOnly: true}
	profileHam100kHz = &regionProfile{presets: presetsNarrow, licensedOnly: true}
)

var swappableEURegions = map[pb.Config_LoRaConfig_RegionCode]bool{
	pb.Config_LoRaConfig_EU_868:   true,
	pb.Config_LoRaConfig_EU_866:   true,
	pb.Config_LoRaConfig_EU_N_868: true,
}

type regionEntry struct {
	code          pb.Config_LoRaConfig_RegionCode
	profile       *regionProfile
	defaultPreset pb.Config_LoRaConfig_ModemPreset
}

// regions is in firmware table order, which fixes group numbering. UNSET is the
// table's terminator there and is not a region here; UA_868 is deprecated and has
// no entry, which clients read as unconstrained.
var regions = []regionEntry{
	{pb.Config_LoRaConfig_US, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_EU_433, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_EU_868, profileEU868, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_EU_866, profileLite, pb.Config_LoRaConfig_LITE_FAST},
	{pb.Config_LoRaConfig_EU_N_868, profileNarrow, pb.Config_LoRaConfig_NARROW_SLOW},
	{pb.Config_LoRaConfig_CN, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_JP, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_ANZ, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_ANZ_433, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_RU, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_KR, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_TW, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_IN, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_NZ_865, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_TH, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_UA_433, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_MY_433, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_MY_919, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_SG_923, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_PH_433, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_PH_868, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_PH_915, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_KZ_433, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_KZ_863, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_NP_865, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_BR_902, profileStd, pb.Config_LoRaConfig_LONG_FAST},
	{pb.Config_LoRaConfig_ITU1_2M, profileHam20kHz, pb.Config_LoRaConfig_TINY_FAST},
	{pb.Config_LoRaConfig_ITU2_2M, profileHam20kHz, pb.Config_LoRaConfig_TINY_FAST},
	{pb.Config_LoRaConfig_ITU3_2M, profileHam20kHz, pb.Config_LoRaConfig_TINY_FAST},
	{pb.Config_LoRaConfig_ITU2_125CM, profileHam100kHz, pb.Config_LoRaConfig_NARROW_SLOW},
	{pb.Config_LoRaConfig_ITU1_70CM, profileHam100kHz, pb.Config_LoRaConfig_NARROW_SLOW},
	{pb.Config_LoRaConfig_ITU2_70CM, profileHam100kHz, pb.Config_LoRaConfig_NARROW_SLOW},
	{pb.Config_LoRaConfig_ITU3_70CM, profileHam100kHz, pb.Config_LoRaConfig_NARROW_SLOW},
	{pb.Config_LoRaConfig_LORA_24, profileStd, pb.Config_LoRaConfig_LONG_FAST},
}

// RegionPresetMap builds the map firmware sends as FromRadio.region_presets. Regions
// with the same profile and default preset share a group, referenced by index, so
// the whole thing fits one packet. A region absent from the map carries no
// constraint, and clients must not restrict it.
//
// Each call returns a fresh message, since callers hand it to a stream.
func RegionPresetMap() *pb.LoRaRegionPresetMap {
	type groupKey struct {
		profile       *regionProfile
		defaultPreset pb.Config_LoRaConfig_ModemPreset
	}
	m := &pb.LoRaRegionPresetMap{}
	index := make(map[groupKey]int)

	for _, r := range regions {
		if len(m.RegionGroups) >= maxRegionGroups {
			break
		}
		key := groupKey{r.profile, r.defaultPreset}
		gi, ok := index[key]
		if !ok {
			if len(m.Groups) >= maxPresetGroups {
				continue
			}
			advertised := r.profile.presets
			if swappableEURegions[r.code] {
				advertised = presetsEUSuperset
			}
			if len(advertised) > maxGroupPresets {
				advertised = advertised[:maxGroupPresets]
			}
			m.Groups = append(m.Groups, &pb.LoRaPresetGroup{
				Presets:       slices.Clone(advertised),
				DefaultPreset: r.defaultPreset,
				LicensedOnly:  r.profile.licensedOnly,
			})
			gi = len(m.Groups) - 1
			index[key] = gi
		}
		m.RegionGroups = append(m.RegionGroups, &pb.LoRaRegionPresets{
			Region:     r.code,
			GroupIndex: uint32(gi),
		})
	}
	return m
}
