package lora

import "testing"

// Expected values were produced by compiling firmware's truncateCoordinate
// (src/mesh/PositionPrecision.cpp, v2.8.0.47db0e3) and running it over these inputs,
// so this pins the Go port to the C behavior including the unsigned wraparound on
// negative coordinates.
func TestTruncateCoordinate(t *testing.T) {
	tests := []struct {
		coordinate int32
		precision  uint32
		want       int32
	}{
		// Precision 0 and >= 32 are pass-through.
		{0, 0, 0},
		{476226196, 0, 476226196},
		{476226196, 32, 476226196},
		{476226196, 33, 476226196},
		{-1223981600, 0, -1223981600},
		{-1223981600, 32, -1223981600},

		// A positive coordinate, roughly 47.62 degrees north.
		{476226196, 1, 1073741824},
		{476226196, 2, 536870912},
		{476226196, 10, 476053504},
		{476226196, 13, 476315648},
		{476226196, 15, 476250112},
		{476226196, 16, 476217344},
		{476226196, 19, 476229632},
		{476226196, 24, 476226176},
		{476226196, 31, 476226197},

		// A negative coordinate, roughly -122.4 degrees. The mask and the half-cell
		// addition both run on the unsigned reinterpretation, so the result can land
		// further from zero than the input.
		{-1223981600, 1, -1073741824},
		{-1223981600, 2, -1610612736},
		{-1223981600, 10, -1222639616},
		{-1223981600, 15, -1224015872},
		{-1223981600, 19, -1223979008},
		{-1223981600, 24, -1223981696},
		{-1223981600, 31, -1223981599},

		// Bounds.
		{-2147483648, 1, -1073741824},
		{-2147483648, 15, -2147418112},
		{-2147483648, 32, -2147483648},
		{0, 15, 65536},
	}

	for _, tt := range tests {
		got := TruncateCoordinate(tt.coordinate, tt.precision)
		if got != tt.want {
			t.Errorf("TruncateCoordinate(%d, %d) = %d, want %d",
				tt.coordinate, tt.precision, got, tt.want)
		}
	}
}

// Truncating an already-truncated coordinate at the same precision must not move it
// again, or a stationary node would drift a cell per broadcast.
func TestTruncateCoordinateIsIdempotent(t *testing.T) {
	coords := []int32{476226196, -1223981600, 0, 1, -1, 2147483647}
	for _, c := range coords {
		for p := uint32(1); p < 32; p++ {
			once := TruncateCoordinate(c, p)
			twice := TruncateCoordinate(once, p)
			if once != twice {
				t.Errorf("TruncateCoordinate(%d, %d) = %d, but re-truncating gave %d",
					c, p, once, twice)
			}
		}
	}
}
