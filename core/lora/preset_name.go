package lora

import pb "github.com/kabili207/meshtastic-go/core/proto"

// presetDisplayNames are firmware's DisplayFormatters::getModemPresetDisplayName
// long names. A primary channel with no name goes by its preset's display name,
// and that name feeds the channel hash, so these must match firmware exactly.
var presetDisplayNames = map[pb.Config_LoRaConfig_ModemPreset]string{
	pb.Config_LoRaConfig_SHORT_TURBO:   "ShortTurbo",
	pb.Config_LoRaConfig_SHORT_SLOW:    "ShortSlow",
	pb.Config_LoRaConfig_SHORT_FAST:    "ShortFast",
	pb.Config_LoRaConfig_MEDIUM_SLOW:   "MediumSlow",
	pb.Config_LoRaConfig_MEDIUM_FAST:   "MediumFast",
	pb.Config_LoRaConfig_MEDIUM_TURBO:  "MediumTurbo",
	pb.Config_LoRaConfig_LONG_SLOW:     "LongSlow",
	pb.Config_LoRaConfig_LONG_FAST:     "LongFast",
	pb.Config_LoRaConfig_LONG_TURBO:    "LongTurbo",
	pb.Config_LoRaConfig_LONG_MODERATE: "LongMod",
	pb.Config_LoRaConfig_LITE_FAST:     "LiteFast",
	pb.Config_LoRaConfig_LITE_SLOW:     "LiteSlow",
	pb.Config_LoRaConfig_NARROW_FAST:   "NarrowFast",
	pb.Config_LoRaConfig_NARROW_SLOW:   "NarrowSlow",
	pb.Config_LoRaConfig_TINY_FAST:     "TinyFast",
	pb.Config_LoRaConfig_TINY_SLOW:     "TinySlow",
}

// PresetDisplayName returns the name firmware gives a modem preset: "Custom" when
// the radio is not using a preset, and "Invalid" for a preset it does not know.
func PresetDisplayName(preset pb.Config_LoRaConfig_ModemPreset, usePreset bool) string {
	if !usePreset {
		return "Custom"
	}
	if name, ok := presetDisplayNames[preset]; ok {
		return name
	}
	return "Invalid"
}
