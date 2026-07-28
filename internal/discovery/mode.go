package discovery

import "github.com/go-ctap/kit/transport"

type Mode = transport.Mode

const (
	ModeAuto         = transport.ModeAuto
	ModeHID          = transport.ModeHID
	ModeSmartCard    = transport.ModeSmartCard
	ModeWindowsProxy = transport.ModeWindowsProxy
)
