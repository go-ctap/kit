package transport

import (
	"context"
	"errors"
	"io/fs"

	"github.com/go-ctap/kit/model/failure"
)

type Mode string

const (
	ModeAuto         Mode = "auto"
	ModeHID          Mode = "hid"
	ModeWindowsProxy Mode = "windows-proxy"
)

// Descriptor is the transport-layer view of a reachable authenticator.
type Descriptor struct {
	Transport    Mode
	Path         string
	Manufacturer string
	Product      string
	Serial       string
	VendorID     uint16
	ProductID    uint16
	UsagePage    uint16
	Usage        uint16
}

// Provider enumerates authenticators for one resolved transport mode.
type Provider interface {
	Check(ctx context.Context) error
	List(ctx context.Context) ([]Descriptor, error)
}

// ProviderResolver resolves the transport provider that should service a command.
type ProviderResolver interface {
	Resolve(ctx context.Context, requested Mode) (ResolvedProvider, error)
}

// ResolvedProvider captures the effective transport after policy resolution.
type ResolvedProvider struct {
	Mode     Mode
	Provider Provider
}

func unsupportedModeError() error {
	return failure.New(failure.CodeTransportModeUnsupported,
		failure.WithPhase(failure.PhaseDiscovery),
	)
}

func transportError(err error) error {
	return normalizeTransportError(err, failure.CodeTransportFailure)
}

func proxyUnavailableError(err error) error {
	return normalizeTransportError(err, failure.CodeTransportProxyUnavailable)
}

func normalizeTransportError(err error, fallback failure.Code) error {
	switch {
	case errors.Is(err, context.Canceled):
		return failure.Wrap(failure.CodeOperationCanceled, err, failure.WithPhase(failure.PhaseDiscovery))
	case errors.Is(err, context.DeadlineExceeded):
		return failure.Wrap(failure.CodeOperationTimeout, err, failure.WithPhase(failure.PhaseDiscovery))
	}

	if errors.Is(err, fs.ErrPermission) {
		return failure.Wrap(
			failure.CodeTransportPermissionDenied,
			err,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	return failure.Wrap(fallback, err, failure.WithPhase(failure.PhaseDiscovery))
}
