package core

import (
	"math"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// Waypoint geofences, mirroring firmware's GeofenceModule so a bridge decides
// "inside" the same way a node on the mesh does.

// earthRadiusMeters is the sphere radius firmware's distance functions use.
const earthRadiusMeters = 6366000

// DistanceMeters returns the surface distance between two points given in
// degrees, the way firmware computes it by default: an equirectangular
// approximation with a polynomial cosine, scaled to a 6366 km sphere. Firmware
// only uses the exact Haversine form when built with MESHTASTIC_TRIG_APPROX=0
// for polar use, so this is what real nodes compare a geofence radius against.
//
// The result is a float32 because firmware's is, and the radius comparison is
// made at that precision.
func DistanceMeters(latA, lonA, latB, lonB float64) float32 {
	if latA == latB && lonA == lonB {
		return 0
	}
	a1 := latA * math.Pi / 180
	a2 := lonA * math.Pi / 180
	b1 := latB * math.Pi / 180
	b2 := lonB * math.Pi / 180

	meanLat := (a1 + b1) / 2
	dLng := b2 - a2
	// A raw longitude difference does not handle the antimeridian: 179.9 and
	// -179.9 are 0.2 degrees apart, not 359.8.
	if dLng > math.Pi {
		dLng -= 2 * math.Pi
	} else if dLng < -math.Pi {
		dLng += 2 * math.Pi
	}
	x := dLng * cosLatitudeApprox(meanLat)
	y := b1 - a1
	return float32(earthRadiusMeters * math.Sqrt(x*x+y*y))
}

// cosLatitudeApprox is firmware's polynomial cosine, kept exact so a point near
// the radius edge lands on the same side here as on a node.
func cosLatitudeApprox(latRad float64) float64 {
	const c1, c2, c3, c4 = 0.9999932946, -0.4999124376, 0.0414877472, -0.0012712095
	x2 := latRad * latRad
	return c1 + x2*(c2+x2*(c3+c4*x2))
}

// WaypointHasGeofence reports whether a waypoint defines any geofence region.
func WaypointHasGeofence(wp *pb.Waypoint) bool {
	return wp != nil && (wp.GeofenceRadius > 0 || wp.BoundingBox != nil)
}

// WaypointContains reports whether a point, in 1e-7 degree integer coordinates,
// falls inside the waypoint's geofence: within the circular radius around the
// waypoint's own position, or inside its bounding box. A waypoint may define
// either or both, and a point inside either counts.
//
// The circle needs the waypoint to carry a position; a radius on a waypoint
// with none is not evaluated, matching what firmware will track. The box carries
// its own corners and needs no position. Both edges are inclusive.
func WaypointContains(wp *pb.Waypoint, latI, lonI int32) bool {
	if wp == nil {
		return false
	}
	if wp.GeofenceRadius > 0 && wp.LatitudeI != nil && wp.LongitudeI != nil {
		if insideRadius(latI, lonI, *wp.LatitudeI, *wp.LongitudeI, wp.GeofenceRadius) {
			return true
		}
	}
	return wp.BoundingBox != nil && insideBox(latI, lonI, wp.BoundingBox)
}

func insideRadius(ptLatI, ptLonI, ctrLatI, ctrLonI int32, radiusMeters uint32) bool {
	if radiusMeters == 0 {
		return false
	}
	meters := DistanceMeters(float64(ptLatI)*1e-7, float64(ptLonI)*1e-7, float64(ctrLatI)*1e-7, float64(ctrLonI)*1e-7)
	return meters <= float32(radiusMeters)
}

// insideBox is an axis-aligned test on integer coordinates. Like firmware it
// assumes west <= east and does not handle a box that straddles the antimeridian.
func insideBox(ptLatI, ptLonI int32, box *pb.BoundingBox) bool {
	return ptLatI >= box.LatitudeSouthI && ptLatI <= box.LatitudeNorthI &&
		ptLonI >= box.LongitudeWestI && ptLonI <= box.LongitudeEastI
}
