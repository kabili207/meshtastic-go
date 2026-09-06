package core

import (
	"testing"

	pb "github.com/kabili207/meshtastic-go/core/proto"
	"google.golang.org/protobuf/proto"
)

// Seattle-ish center, in 1e-7 degrees.
const (
	centerLatI = int32(476226196)
	centerLonI = int32(-1223981600)
)

func circleWaypoint(radius uint32) *pb.Waypoint {
	return &pb.Waypoint{
		LatitudeI:      proto.Int32(centerLatI),
		LongitudeI:     proto.Int32(centerLonI),
		GeofenceRadius: radius,
	}
}

func TestWaypointHasGeofence(t *testing.T) {
	tests := []struct {
		name string
		wp   *pb.Waypoint
		want bool
	}{
		{"nil", nil, false},
		{"plain waypoint", &pb.Waypoint{Name: "x"}, false},
		{"radius only", circleWaypoint(100), true},
		{"box only", &pb.Waypoint{BoundingBox: &pb.BoundingBox{}}, true},
		{"radius zero is not a geofence", circleWaypoint(0), false},
	}
	for _, tt := range tests {
		if got := WaypointHasGeofence(tt.wp); got != tt.want {
			t.Errorf("%s: WaypointHasGeofence = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWaypointContainsRadius(t *testing.T) {
	// About 250 m north of the center: 0.00225 degrees of latitude.
	northI := centerLatI + 22500
	// About 2.5 km north.
	farNorthI := centerLatI + 225000

	tests := []struct {
		name       string
		wp         *pb.Waypoint
		latI, lonI int32
		want       bool
	}{
		{"center is inside", circleWaypoint(100), centerLatI, centerLonI, true},
		{"250m inside a 500m circle", circleWaypoint(500), northI, centerLonI, true},
		{"250m outside a 100m circle", circleWaypoint(100), northI, centerLonI, false},
		{"2.5km outside a 1km circle", circleWaypoint(1000), farNorthI, centerLonI, false},
		{"radius zero never contains", circleWaypoint(0), centerLatI, centerLonI, false},
		{"radius without a position is not evaluated", &pb.Waypoint{GeofenceRadius: 1000}, 0, 0, false},
		{"nil waypoint", nil, centerLatI, centerLonI, false},
	}
	for _, tt := range tests {
		if got := WaypointContains(tt.wp, tt.latI, tt.lonI); got != tt.want {
			t.Errorf("%s: WaypointContains = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWaypointContainsBox(t *testing.T) {
	box := &pb.BoundingBox{
		LongitudeWestI: -1224000000,
		LatitudeSouthI: 476000000,
		LongitudeEastI: -1223900000,
		LatitudeNorthI: 476400000,
	}
	wp := &pb.Waypoint{BoundingBox: box}

	tests := []struct {
		name       string
		latI, lonI int32
		want       bool
	}{
		{"interior", 476200000, -1223950000, true},
		{"south-west corner is inclusive", box.LatitudeSouthI, box.LongitudeWestI, true},
		{"north-east corner is inclusive", box.LatitudeNorthI, box.LongitudeEastI, true},
		{"one unit south", box.LatitudeSouthI - 1, -1223950000, false},
		{"one unit north", box.LatitudeNorthI + 1, -1223950000, false},
		{"one unit west", 476200000, box.LongitudeWestI - 1, false},
		{"one unit east", 476200000, box.LongitudeEastI + 1, false},
	}
	for _, tt := range tests {
		if got := WaypointContains(wp, tt.latI, tt.lonI); got != tt.want {
			t.Errorf("%s: WaypointContains = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// A waypoint with both regions contains a point inside either one.
func TestWaypointContainsEither(t *testing.T) {
	wp := circleWaypoint(100)
	wp.BoundingBox = &pb.BoundingBox{
		LongitudeWestI: -1230000000, LatitudeSouthI: 480000000,
		LongitudeEastI: -1229000000, LatitudeNorthI: 481000000,
	}
	if !WaypointContains(wp, centerLatI, centerLonI) {
		t.Error("point inside the circle but outside the box was rejected")
	}
	if !WaypointContains(wp, 480500000, -1229500000) {
		t.Error("point inside the box but outside the circle was rejected")
	}
	if WaypointContains(wp, 470000000, -1200000000) {
		t.Error("point outside both was accepted")
	}
}

// Expected values come from compiling firmware's default latLongToMeter (the
// MESHTASTIC_TRIG_APPROX=1 branch of src/gps/GeoCoord.cpp at v2.8.0.47db0e3) and
// running it over these pairs. Compared exactly at float32, since that is the
// precision firmware compares a geofence radius at.
func TestDistanceMetersMatchesFirmware(t *testing.T) {
	tests := []struct {
		latA, lonA, latB, lonB float64
		want                   float32
	}{
		{47.6226196, -122.3981600, 47.6226196, -122.3981600, 0},
		{47.6226196, -122.3981600, 47.6248700, -122.3981600, 250.036682},
		{47.6226196, -122.3981600, 47.6226196, -122.3948300, 249.376846},
		{47.6226196, -122.3981600, 47.6300000, -122.3900000, 1022.64557},
		// Straddles the antimeridian: 0.2 degrees apart, not 359.8.
		{0.0, 179.9, 0.0, -179.9, 22221.3828},
		{-33.8688000, 151.2093000, -33.8600000, 151.2200000, 1389.43054},
		{64.1466000, -21.9426000, 64.1500000, -21.9300000, 717.868225},
		{51.5074000, -0.1278000, 48.8566000, 2.3522000, 343333.594},
	}
	for _, tt := range tests {
		if got := DistanceMeters(tt.latA, tt.lonA, tt.latB, tt.lonB); got != tt.want {
			t.Errorf("DistanceMeters(%v,%v,%v,%v) = %v, want %v", tt.latA, tt.lonA, tt.latB, tt.lonB, got, tt.want)
		}
	}
}
