//go:build darwin || linux

package devicewatch

import (
	"fmt"

	"github.com/telesma-app/kit/transport"
)

func resolveHIDMode(requested transport.Mode) (transport.Mode, error) {
	switch requested {
	case transport.ModeAuto, transport.ModeHID:
		return transport.ModeHID, nil
	default:
		return "", fmt.Errorf("ctapkit: unsupported transport mode %q", requested)
	}
}
