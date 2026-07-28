package transport

import (
	"context"
	"errors"
	"io/fs"
	"sync"

	ctapdiscover "github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/options"
	ghid "github.com/go-ctap/hid"
	"github.com/go-ctap/kit/model/failure"
)

type Mode string

const (
	ModeAuto         Mode = "auto"
	ModeHID          Mode = "hid"
	ModeSmartCard    Mode = "smart-card"
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
	ATR          []byte
}

// Discover returns FIDO devices reachable through the requested transport
// policy.
func Discover(ctx context.Context, requested Mode) ([]Descriptor, error) {
	if requested == "" {
		requested = ModeAuto
	}

	switch requested {
	case ModeAuto:
		hidMode, err := resolveMode(ModeAuto)
		if err != nil {
			return nil, err
		}

		return discoverAvailable(ctx,
			func(ctx context.Context) ([]Descriptor, error) {
				return discoverHID(ctx, hidMode)
			},
			discoverSmartCards,
		)
	case ModeHID, ModeWindowsProxy:
		mode, err := resolveMode(requested)
		if err != nil {
			return nil, err
		}

		return discoverHID(ctx, mode)
	case ModeSmartCard:
		return discoverSmartCards(ctx)
	default:
		return nil, unsupportedModeError()
	}
}

func discoverHID(ctx context.Context, mode Mode) ([]Descriptor, error) {
	infos, err := ctapdiscover.EnumerateFIDODevices(ctx, discoveryOptions(mode)...)
	if err != nil {
		return nil, discoveryError(mode, err)
	}

	return descriptorsFromDeviceInfos(mode, infos), nil
}

// Events reports when the set of reachable FIDO devices may have changed.
//
//goland:noinspection GoUnusedExportedFunction
func Events(ctx context.Context, requested Mode) (<-chan Event, error) {
	if requested == "" {
		requested = ModeAuto
	}

	switch requested {
	case ModeAuto:
		hidMode, err := resolveMode(ModeAuto)
		if err != nil {
			return nil, err
		}

		return openAvailableEvents(ctx,
			func(ctx context.Context) (<-chan Event, error) {
				return hidEvents(ctx, hidMode)
			},
			smartCardEvents,
		)
	case ModeHID, ModeWindowsProxy:
		mode, err := resolveMode(requested)
		if err != nil {
			return nil, err
		}

		return hidEvents(ctx, mode)
	case ModeSmartCard:
		return smartCardEvents(ctx)
	default:
		return nil, unsupportedModeError()
	}
}

// Event reports that the set of reachable FIDO devices may have changed.
type Event struct {
	Err error
}

func hidEvents(ctx context.Context, mode Mode) (<-chan Event, error) {
	events, err := ctapdiscover.Events(ctx, discoveryOptions(mode)...)
	if err != nil {
		return nil, discoveryError(mode, err)
	}

	out := make(chan Event)
	go func() {
		defer close(out)

		for event := range events {
			select {
			case out <- Event{Err: event.Err}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}

func discoveryOptions(mode Mode) []options.Option {
	if mode == ModeWindowsProxy {
		return []options.Option{options.WithUseNamedPipes()}
	}

	return nil
}

func discoveryError(mode Mode, err error) error {
	if mode == ModeWindowsProxy {
		return normalizeTransportError(err, failure.CodeTransportProxyUnavailable)
	}

	return normalizeTransportError(err, failure.CodeTransportFailure)
}

func descriptorsFromDeviceInfos(mode Mode, infos []*ghid.DeviceInfo) []Descriptor {
	descriptors := make([]Descriptor, 0, len(infos))
	for _, info := range infos {
		descriptors = append(descriptors, Descriptor{
			Transport:    mode,
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

type discoverFunc func(context.Context) ([]Descriptor, error)

func discoverAvailable(ctx context.Context, sources ...discoverFunc) ([]Descriptor, error) {
	var descriptors []Descriptor
	var sourceErr error
	var succeeded bool
	for _, source := range sources {
		found, err := source(ctx)
		if err != nil {
			sourceErr = errors.Join(sourceErr, err)
			continue
		}

		succeeded = true
		descriptors = append(descriptors, found...)
	}

	if succeeded {
		return descriptors, nil
	}

	return nil, sourceErr
}

type eventsFunc func(context.Context) (<-chan Event, error)

func openAvailableEvents(ctx context.Context, sources ...eventsFunc) (<-chan Event, error) {
	var inputs []<-chan Event
	var sourceErr error
	for _, source := range sources {
		events, err := source(ctx)
		if err != nil {
			sourceErr = errors.Join(sourceErr, err)
			continue
		}

		inputs = append(inputs, events)
	}

	if len(inputs) == 0 {
		return nil, sourceErr
	}

	out := make(chan Event)
	var producers sync.WaitGroup
	producers.Add(len(inputs))
	for _, input := range inputs {
		go func() {
			defer producers.Done()

			for event := range input {
				select {
				case out <- event:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		producers.Wait()
		close(out)
	}()

	return out, nil
}

func unsupportedModeError() error {
	return failure.New(failure.CodeTransportModeUnsupported,
		failure.WithPhase(failure.PhaseDiscovery),
	)
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
