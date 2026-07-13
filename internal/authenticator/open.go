package authenticator

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/kit/transport"
)

// Open opens the private CTAP authenticator implementation for a transport path.
func Open(ctx context.Context, mode transport.Mode, path string) (Device, error) {
	opts := []options.Option{options.WithContext(ctx)}

	switch mode {
	case transport.ModeHID:
	case transport.ModeWindowsProxy:
		opts = append(opts, options.WithUseNamedPipes())
	default:
		return nil, fmt.Errorf("%w: %s", transport.ErrUnsupportedMode, mode)
	}

	device, err := ctapdevice.New(path, opts...)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission):
			return nil, fmt.Errorf("%w: %v", transport.ErrPermissionDenied, err)
		case mode == transport.ModeWindowsProxy:
			return nil, fmt.Errorf("%w: %v", transport.ErrProxyUnavailable, err)
		default:
			return nil, err
		}
	}

	return device, nil
}
