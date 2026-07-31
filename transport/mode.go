package transport

// Mode selects the transport policy for a DeviceManager.
type Mode string

const (
	ModeAuto         Mode = "auto"
	ModeHID          Mode = "hid"
	ModeSmartCard    Mode = "smart-card"
	ModeWindowsProxy Mode = "windows-proxy"
)
