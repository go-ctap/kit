package device

import "errors"

var (
	ErrSelectionRequired = errors.New("ctapkit: device selection required")
	ErrUnavailable       = errors.New("ctapkit: device unavailable")
	ErrBusy              = errors.New("ctapkit: device busy")
)
