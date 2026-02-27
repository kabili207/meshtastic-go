package core

import pb "github.com/kabili207/meshtastic-go/core/proto"

// IsUnmessageableRole returns true if the given device role indicates a node
// that should not receive direct messages. These roles are infrastructure
// nodes (repeaters, routers) or passive sensors/trackers.
//
// Based on Meshtastic Android client behavior:
// https://github.com/meshtastic/Meshtastic-Android
func IsUnmessageableRole(role pb.Config_DeviceConfig_Role) bool {
	switch role {
	case pb.Config_DeviceConfig_REPEATER,
		pb.Config_DeviceConfig_ROUTER,
		pb.Config_DeviceConfig_ROUTER_LATE,
		pb.Config_DeviceConfig_SENSOR,
		pb.Config_DeviceConfig_TRACKER,
		pb.Config_DeviceConfig_TAK,
		pb.Config_DeviceConfig_TAK_TRACKER:
		return true
	default:
		return false
	}
}

// IsUnmessageable returns true if the given user should not receive direct
// messages. Checks the explicit IsUnmessagable flag first, falling back to
// role-based detection.
func IsUnmessageable(user *pb.User) bool {
	if user.IsUnmessagable != nil {
		return *user.IsUnmessagable
	}
	return IsUnmessageableRole(user.Role)
}
