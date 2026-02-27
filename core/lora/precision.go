package lora

// PrecisionBitsToMeters converts Meshtastic position precision bits to an
// approximate uncertainty radius in meters. The mapping matches the firmware
// and Android client behavior.
//
// Common values: 10 = LOW (~23km), 16 = MED (~364m), 32 = HIGH (0m).
// Returns 0 for unrecognized or zero input.
func PrecisionBitsToMeters(bits uint32) uint32 {
	if v, ok := bitsToMeters[bits]; ok {
		return v
	}
	return 0
}

// MetersToPrecisionBits converts an uncertainty radius in meters to the
// closest Meshtastic position precision bits value. Higher bit counts mean
// higher precision (smaller uncertainty).
//
// Returns 0 for negative input.
func MetersToPrecisionBits(meters float32) uint32 {
	if meters < 0 {
		return 0
	}
	// Walk thresholds from coarsest to finest; return the first bits value
	// whose meter range covers the input.
	for _, t := range metersToThresholds {
		if meters >= t.threshold {
			return t.bits
		}
	}
	return 20 // finest granularity in the threshold table
}

var bitsToMeters = map[uint32]uint32{
	2:  5976446,
	3:  2988223,
	4:  1494111,
	5:  747055,
	6:  373527,
	7:  186763,
	8:  93381,
	9:  46690,
	10: 23345,
	11: 11672,
	12: 5836,
	13: 2918,
	14: 1459,
	15: 729,
	16: 364,
	17: 182,
	18: 91,
	19: 45,
	20: 22,
	21: 11,
	22: 5,
	23: 2,
	24: 1,
	32: 0,
}

type metersThreshold struct {
	threshold float32
	bits      uint32
}

// Ordered from coarsest to finest so the first match wins.
var metersToThresholds = []metersThreshold{
	{23300, 10},
	{11700, 11},
	{5800, 12},
	{2900, 13},
	{1500, 14},
	{729, 15},
	{364, 16},
	{182, 17},
	{91, 18},
	{45, 19},
}
