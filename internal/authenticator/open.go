package authenticator

import (
	"context"
	"errors"
	"io/fs"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/options"
	ctapiso7816 "github.com/go-ctap/ctap/transport/iso7816"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
	"github.com/go-ctap/pcsc"
)

// Open opens the private CTAP authenticator implementation for a transport path.
func Open(ctx context.Context, mode transport.Mode, path string) (*Opened, error) {
	var opts []options.Option

	switch mode {
	case transport.ModeHID:
	case transport.ModeWindowsProxy:
		opts = append(opts, options.WithUseNamedPipes())
	case transport.ModeSmartCard:
	default:
		return nil, failure.New(failure.CodeTransportModeUnsupported,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}

	if recorder := kitlog.RecorderFrom(ctx); recorder != nil {
		opts = append(opts, options.WithDiagnosticSink(kitlog.NewCTAPSink(recorder)))
	}

	var (
		device *ctapdevice.Device
		err    error
	)
	if mode == transport.ModeSmartCard {
		device, err = openSmartCard(ctx, path, opts...)
	} else {
		device, err = ctapdevice.OpenHID(ctx, path, opts...)
	}
	if err == nil {
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

	switch {
	case errors.Is(err, context.Canceled):
		return nil, failure.Wrap(
			failure.CodeOperationCanceled,
			err,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	case errors.Is(err, context.DeadlineExceeded):
		return nil, failure.Wrap(
			failure.CodeOperationTimeout,
			err,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	case errors.Is(err, fs.ErrPermission):
		return nil, failure.Wrap(
			failure.CodeTransportPermissionDenied,
			err,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	case errors.Is(err, pcsc.ErrNoAccess):
		return nil, failure.Wrap(
			failure.CodeTransportPermissionDenied,
			err,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	case mode == transport.ModeWindowsProxy:
		return nil, failure.Wrap(
			failure.CodeTransportProxyUnavailable,
			err,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	default:
		return nil, failure.Wrap(
			failure.CodeTransportFailure,
			err,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}
}

func openSmartCard(
	ctx context.Context,
	reader string,
	opts ...options.Option,
) (*ctapdevice.Device, error) {
	card, err := pcsc.Open(reader, pcsc.WithShareMode(pcsc.ShareModeExclusive))
	if err != nil {
		return nil, err
	}

	isoTransport, err := ctapiso7816.New(ctx, card)
	if err != nil {
		return nil, errors.Join(err, card.Close())
	}

	device, err := ctapdevice.New(ctx, isoTransport, opts...)
	if err != nil {
		return nil, errors.Join(err, isoTransport.Close())
	}

	return device, nil
}
