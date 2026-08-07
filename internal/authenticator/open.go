package authenticator

import (
	"context"
	"errors"
	"io/fs"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	directhid "github.com/go-ctap/ctap/backend/hid"
	"github.com/go-ctap/ctap/backend/hidproxy"
	ctappcsc "github.com/go-ctap/ctap/backend/pcsc"
	"github.com/go-ctap/ctap/options"
	ctaptransport "github.com/go-ctap/ctap/transport"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
	"github.com/go-ctap/pcsc"
)

// Open opens the private CTAP authenticator implementation for a transport path.
func Open(ctx context.Context, mode transport.Mode, path string) (*Opened, error) {
	var (
		deviceTransport ctaptransport.Device
		err             error
	)
	switch mode {
	case transport.ModeHID:
		deviceTransport, err = directhid.Open(ctx, path)
	case transport.ModeWindowsProxy:
		deviceTransport, err = hidproxy.Open(ctx, path)
	case transport.ModeSmartCard:
		deviceTransport, err = ctappcsc.Open(ctx, path)
	default:
		return nil, failure.New(failure.CodeTransportModeUnsupported,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}

	var opts []options.Option
	if recorder := kitlog.RecorderFrom(ctx); recorder != nil {
		opts = append(opts, options.WithDiagnosticSink(kitlog.NewCTAPSink(recorder)))
	}

	if err == nil {
		device, newErr := ctapdevice.New(ctx, deviceTransport, opts...)
		if newErr != nil {
			err = errors.Join(newErr, deviceTransport.Close())
		} else {
			return &Opened{
				Lifecycle:           device,
				Info:                device,
				Vendor:              device,
				Tokens:              device,
				CredentialInventory: device,
				Credentials:         device,
				WebAuthn:            device,
				LargeBlobs:          device,
				ConfigStatus:        device,
				Config:              device,
				Bio:                 device,
			}, nil
		}
	}

	code := failure.CodeTransportFailure
	switch {
	case errors.Is(err, context.Canceled):
		code = failure.CodeOperationCanceled
	case errors.Is(err, context.DeadlineExceeded):
		code = failure.CodeOperationTimeout
	case errors.Is(err, fs.ErrPermission), errors.Is(err, pcsc.ErrNoAccess):
		code = failure.CodeTransportPermissionDenied
	case mode == transport.ModeWindowsProxy:
		code = failure.CodeTransportProxyUnavailable
	}

	return nil, failure.Wrap(
		code,
		err,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}
