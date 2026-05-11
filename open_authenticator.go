package ctapkit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	ctapdevice "github.com/go-ctap/ctaphid/pkg/device"
	"github.com/go-ctap/ctaphid/pkg/options"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/transport"
)

type authenticatorOpenFunc func(ctx context.Context, mode transport.Mode, path string) (authenticator.Device, error)

func openAuthenticator(ctx context.Context, mode transport.Mode, path string) (authenticator.Device, error) {
	opts := []options.Option{options.WithContext(ctx)}

	switch mode {
	case transport.ModeHID:
	case transport.ModeWindowsProxy:
		opts = append(opts, options.WithUseNamedPipes())
	default:
		return nil, fmt.Errorf("%w: %s", transport.ErrUnsupportedMode, mode)
	}

	dev, err := ctapdevice.New(path, opts...)
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

	return dev, nil
}
