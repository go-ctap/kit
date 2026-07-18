//go:build linux || darwin

package transport

func resolveMode(requested Mode) (Mode, error) {
	switch requested {
	case ModeAuto, ModeHID:
		return ModeHID, nil
	default:
		return "", unsupportedModeError()
	}
}
