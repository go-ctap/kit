package ctapkit

import (
	"context"
	"strconv"
	"strings"

	rtdevice "github.com/go-ctap/kit/internal/device"
	"github.com/go-ctap/kit/internal/vendorinfo"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
	"github.com/samber/lo"
)

// Device is an opaque handle to one discovered authenticator.
type Device struct {
	report report.DeviceReport
	valid  bool
}

// DiscoverDevices returns authenticators reachable through the configured transport policy.
func DiscoverDevices(ctx context.Context, mode transport.Mode) ([]Device, error) {
	return discoverDevices(ctx, transport.Discover, mode)
}

// SelectDevice resolves a user-facing selector against one discovery snapshot.
func SelectDevice(devices []Device, selector string) (Device, error) {
	selector = strings.TrimSpace(selector)

	switch {
	case len(devices) == 0:
		return Device{}, failure.New(failure.CodeDeviceUnavailable,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	case selector == "" && len(devices) == 1:
		return devices[0], nil
	case selector == "":
		return Device{}, failure.New(failure.CodeDeviceSelectionRequired,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	device, ok := lo.Find(devices, func(device Device) bool {
		r := device.Report()
		return r.Fingerprint == selector || r.OrdinalAlias == selector
	})
	if ok {
		return device, nil
	}

	return Device{}, failure.New(failure.CodeDeviceNotFound,
		failure.WithPhase(failure.PhaseDiscovery),
	)
}

// Report returns public metadata for a discovered authenticator.
func (d Device) Report() report.DeviceReport {
	if !d.valid {
		return report.DeviceReport{}
	}

	return d.report
}

type discoverTransportFunc func(context.Context, transport.Mode) (transport.Mode, []transport.Descriptor, error)

func discoverDevices(ctx context.Context, discover discoverTransportFunc, mode transport.Mode) ([]Device, error) {
	if mode == "" {
		mode = transport.ModeAuto
	}

	mode, descriptors, err := discover(ctx, mode)
	if err != nil {
		return nil, err
	}

	return lo.Map(descriptors, func(descriptor transport.Descriptor, index int) Device {
		return newDevice(index, mode, descriptor)
	}), nil
}

func newDevice(index int, mode transport.Mode, descriptor transport.Descriptor) Device {
	return Device{
		report: report.DeviceReport{
			Fingerprint:  rtdevice.Fingerprint(mode, descriptor.Path),
			OrdinalAlias: strconv.Itoa(index + 1),
			Transport:    mode,
			Path:         descriptor.Path,
			Manufacturer: descriptor.Manufacturer,
			Product:      descriptor.Product,
			Serial:       descriptor.Serial,
			VendorID:     descriptor.VendorID,
			ProductID:    descriptor.ProductID,
			Vendor:       vendorinfo.Classify(descriptor.VendorID),
		},
		valid: true,
	}
}
