//go:build windows

package transport

import (
	"golang.org/x/sys/windows"
)

func resolveMode(requested Mode) (Mode, error) {
	return resolveWindowsMode(requested, windows.GetCurrentProcessToken().IsElevated())
}

func resolveWindowsMode(requested Mode, elevated bool) (Mode, error) {
	switch requested {
	case ModeAuto:
		if elevated {
			return ModeHID, nil
		}

		return ModeWindowsProxy, nil
	case ModeHID:
		return ModeHID, nil
	case ModeWindowsProxy:
		return ModeWindowsProxy, nil
	default:
		return "", unsupportedModeError()
	}
}
