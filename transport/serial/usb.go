package serial

import (
	"log/slog"

	"go.bug.st/serial/enumerator"
)

type usbDevice struct {
	VID string
	PID string
}

// knownDevices contains VID/PID pairs for known Meshtastic-compatible USB devices.
var knownDevices = []usbDevice{
	// rak4631_19003
	{VID: "239A", PID: "8029"},
	// CP210x UART Bridge - commonly found on Heltec and other devices.
	{VID: "10C4", PID: "EA60"},
	// CH9102 - found on some Heltec boards
	{VID: "1A86", PID: "55D4"},
	// CH340 - common USB-to-serial adapter
	{VID: "1A86", PID: "7523"},
}

// GetPorts returns a list of serial ports that match known Meshtastic device VID/PIDs.
func GetPorts() []string {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		slog.Error("failed to enumerate serial ports", "error", err)
		return nil
	}

	var foundDevices []string
	for _, port := range ports {
		if port.IsUSB {
			for _, device := range knownDevices {
				if device.VID == port.VID && device.PID == port.PID {
					foundDevices = append(foundDevices, port.Name)
					break
				}
			}
		}
	}
	return foundDevices
}

// GetAllPorts returns all serial ports, not filtered by known devices.
func GetAllPorts() ([]string, error) {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, port := range ports {
		names = append(names, port.Name)
	}
	return names, nil
}
