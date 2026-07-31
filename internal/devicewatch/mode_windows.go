//go:build windows

package devicewatch

import (
	"fmt"

	"github.com/go-ctap/kit/transport"
	"golang.org/x/sys/windows"
)

func resolveHIDMode(requested transport.Mode) (transport.Mode, error) {
	switch requested {
	case transport.ModeAuto:
		if windows.GetCurrentProcessToken().IsElevated() {
			return transport.ModeHID, nil
		}

		return transport.ModeWindowsProxy, nil
	case transport.ModeHID, transport.ModeWindowsProxy:
		return requested, nil
	default:
		return "", fmt.Errorf("ctapkit: unsupported transport mode %q", requested)
	}
}
