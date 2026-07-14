package authenticator

import (
	"context"
	"errors"
	"io/fs"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
)

// Open opens the private CTAP authenticator implementation for a transport path.
func Open(ctx context.Context, mode transport.Mode, path string) (Device, error) {
	var opts []options.Option

	switch mode {
	case transport.ModeHID:
	case transport.ModeWindowsProxy:
		opts = append(opts, options.WithUseNamedPipes())
	default:
		return nil, failure.New(failure.CodeTransportModeUnsupported,
			failure.WithPhase(failure.PhaseSession),
		)
	}

	device, err := ctapdevice.OpenHID(ctx, path, opts...)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, failure.Wrap(
				failure.CodeOperationCanceled,
				err,
				failure.WithPhase(failure.PhaseSession),
			)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, failure.Wrap(
				failure.CodeOperationTimeout,
				err,
				failure.WithPhase(failure.PhaseSession),
			)
		case errors.Is(err, fs.ErrPermission):
			return nil, failure.Wrap(
				failure.CodeTransportPermissionDenied,
				err,
				failure.WithPhase(failure.PhaseSession),
			)
		case mode == transport.ModeWindowsProxy:
			return nil, failure.Wrap(
				failure.CodeTransportProxyUnavailable,
				err,
				failure.WithPhase(failure.PhaseSession),
			)
		default:
			return nil, failure.Wrap(
				failure.CodeTransportFailure,
				err,
				failure.WithPhase(failure.PhaseSession),
			)
		}
	}

	return device, nil
}
