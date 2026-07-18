package transport

import (
	"context"
	"errors"
	"io/fs"

	ctapdiscover "github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/options"
	ghid "github.com/go-ctap/hid"
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
	Path         string
	Manufacturer string
	Product      string
	Serial       string
	VendorID     uint16
	ProductID    uint16
}

// Discover returns the effective transport mode and the FIDO devices reachable
// through it.
func Discover(ctx context.Context, requested Mode) (Mode, []Descriptor, error) {
	mode, err := resolveMode(requested)
	if err != nil {
		return "", nil, err
	}

	infos, err := ctapdiscover.EnumerateFIDODevices(ctx, discoveryOptions(mode)...)
	if err != nil {
		return "", nil, discoveryError(mode, err)
	}

	return mode, descriptorsFromDeviceInfos(infos), nil
}

// Events reports when the set of reachable FIDO devices may have changed.
func Events(ctx context.Context, requested Mode) (<-chan ctapdiscover.Event, error) {
	mode, err := resolveMode(requested)
	if err != nil {
		return nil, err
	}

	events, err := ctapdiscover.Events(ctx, discoveryOptions(mode)...)
	if err != nil {
		return nil, discoveryError(mode, err)
	}

	return events, nil
}

func discoveryOptions(mode Mode) []options.Option {
	if mode == ModeWindowsProxy {
		return []options.Option{options.WithUseNamedPipes()}
	}

	return nil
}

func discoveryError(mode Mode, err error) error {
	if mode == ModeWindowsProxy {
		return proxyUnavailableError(err)
	}

	return transportError(err)
}

func descriptorsFromDeviceInfos(infos []*ghid.DeviceInfo) []Descriptor {
	descriptors := make([]Descriptor, 0, len(infos))
	for _, info := range infos {
		descriptors = append(descriptors, Descriptor{
			Path:         info.Path,
			Manufacturer: info.MfrStr,
			Product:      info.ProductStr,
			Serial:       info.SerialNbr,
			VendorID:     info.VendorID,
			ProductID:    info.ProductID,
		})
	}

	return descriptors
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
