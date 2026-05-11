package ctapkit

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	rtdevice "github.com/go-ctap/kit/internal/device"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
	"github.com/samber/lo"
)

// Device is an opaque handle to one discovered authenticator.
type Device struct {
	report report.DeviceReport
	valid  bool
}

// DiscoverOption configures device discovery.
type DiscoverOption func(*discoverConfig)

type discoverConfig struct {
	mode transport.Mode
}

// WithTransport overrides the default automatic transport policy for discovery.
func WithTransport(mode transport.Mode) DiscoverOption {
	return func(config *discoverConfig) {
		config.mode = mode
	}
}

// DiscoverDevices returns authenticators reachable through the configured transport policy.
func DiscoverDevices(ctx context.Context, opts ...DiscoverOption) ([]Device, error) {
	return discoverDevices(ctx, transport.NewDefaultResolver(), opts...)
}

// SelectDevice resolves a user-facing selector against one discovery snapshot.
func SelectDevice(devices []Device, selector string) (Device, error) {
	selector = strings.TrimSpace(selector)

	switch {
	case len(devices) == 0:
		return Device{}, runtimeDeviceError(fmt.Errorf("%w: no authenticators discovered", rtdevice.ErrUnavailable))
	case selector == "" && len(devices) == 1:
		return devices[0], nil
	case selector == "":
		return Device{}, runtimeDeviceError(fmt.Errorf("%w: multiple authenticators available", rtdevice.ErrSelectionRequired))
	}

	device, ok := lo.Find(devices, func(device Device) bool {
		r := device.Report()
		return r.DeviceID == selector || r.OrdinalAlias == selector
	})
	if ok {
		return device, nil
	}

	return Device{}, runtimeDeviceError(fmt.Errorf("%w: no authenticator matches %q", rtdevice.ErrUnavailable, selector))
}

// Report returns public metadata for a discovered authenticator.
func (d Device) Report() report.DeviceReport {
	if !d.valid {
		return report.DeviceReport{}
	}

	return d.report
}

func discoverDevices(ctx context.Context, resolver transport.ProviderResolver, opts ...DiscoverOption) ([]Device, error) {
	config := &discoverConfig{
		mode: transport.ModeAuto,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(config)
		}
	}

	resolved, err := resolver.Resolve(ctx, config.mode)
	if err != nil {
		return nil, runtimeDeviceError(err)
	}

	descriptors, err := resolved.Provider.List(ctx)
	if err != nil {
		return nil, runtimeDeviceError(err)
	}

	return lo.Map(descriptors, func(descriptor transport.Descriptor, index int) Device {
		return newDevice(index, resolved.Mode, descriptor)
	}), nil
}

func newDevice(index int, mode transport.Mode, descriptor transport.Descriptor) Device {
	return Device{
		report: report.DeviceReport{
			DeviceID:     rtdevice.ID(descriptor.VendorID, descriptor.ProductID, descriptor.Serial, descriptor.Path),
			OrdinalAlias: strconv.Itoa(index + 1),
			StableID:     rtdevice.Stable(descriptor.VendorID, descriptor.ProductID, descriptor.Serial, descriptor.Path),
			Transport:    mode,
			Path:         descriptor.Path,
			Manufacturer: descriptor.Manufacturer,
			Product:      descriptor.Product,
			Serial:       descriptor.Serial,
			VendorID:     descriptor.VendorID,
			ProductID:    descriptor.ProductID,
		},
		valid: true,
	}
}
