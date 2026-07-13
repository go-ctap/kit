package ctapkit

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/kit/model"
	modelreport "github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

type fakeDiscoveryProvider struct {
	list []transport.Descriptor
	err  error
}

func (p *fakeDiscoveryProvider) Check(context.Context) error {
	return nil
}

func (p *fakeDiscoveryProvider) List(context.Context) ([]transport.Descriptor, error) {
	if p.err != nil {
		return nil, p.err
	}

	return p.list, nil
}

type fakeDiscoveryResolver struct {
	resolved  transport.ResolvedProvider
	err       error
	requested transport.Mode
}

func (r *fakeDiscoveryResolver) Resolve(_ context.Context, requested transport.Mode) (transport.ResolvedProvider, error) {
	r.requested = requested
	if r.err != nil {
		return transport.ResolvedProvider{}, r.err
	}

	return r.resolved, nil
}

func TestDiscoverDevicesReturnsOpaqueDevicesWithReports(t *testing.T) {
	resolver := newFakeDiscoveryResolver([]transport.Descriptor{{
		Path:         "hid://one",
		Manufacturer: "Yubico",
		Product:      "YubiKey 5C NFC",
		Serial:       "12345678",
		VendorID:     0x1050,
		ProductID:    0x0407,
	}})

	devices, err := discoverDevices(context.Background(), resolver)
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}

	if resolver.requested != transport.ModeAuto {
		t.Fatalf("requested mode = %q, want %q", resolver.requested, transport.ModeAuto)
	}

	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}

	report := devices[0].Report()
	if report.DeviceID == "" || report.OrdinalAlias != "1" || report.Transport != transport.ModeHID || report.Path != "hid://one" || report.Manufacturer != "Yubico" || report.Product != "YubiKey 5C NFC" || report.Serial != "12345678" || report.VendorID != 0x1050 || report.ProductID != 0x0407 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Vendor != modelreport.VendorYubico {
		t.Fatalf("vendor = %q, want %q", report.Vendor, modelreport.VendorYubico)
	}
}

func TestDiscoverDevicesWithTransportPassesRequestedMode(t *testing.T) {
	resolver := newFakeDiscoveryResolver([]transport.Descriptor{{
		Path:      "hid://one",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}})

	if _, err := discoverDevices(context.Background(), resolver, WithTransport(transport.ModeHID)); err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}

	if resolver.requested != transport.ModeHID {
		t.Fatalf("requested mode = %q, want %q", resolver.requested, transport.ModeHID)
	}
}

func TestSelectDeviceUsesDiscoverySnapshot(t *testing.T) {
	devices, err := discoverDevices(context.Background(), newFakeDiscoveryResolver([]transport.Descriptor{
		{
			Path:      "hid://one",
			Serial:    "12345678",
			VendorID:  0x1050,
			ProductID: 0x0407,
		},
		{
			Path:      "hid://two",
			VendorID:  0x1050,
			ProductID: 0x0408,
		},
	}))
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}

	selected, err := SelectDevice(devices, devices[0].Report().DeviceID)
	if err != nil {
		t.Fatalf("SelectDevice(id): %v", err)
	}
	if selected.Report().Path != "hid://one" {
		t.Fatalf("selected by id path = %q, want hid://one", selected.Report().Path)
	}

	selected, err = SelectDevice(devices, devices[1].Report().OrdinalAlias)
	if err != nil {
		t.Fatalf("SelectDevice(alias): %v", err)
	}
	if selected.Report().Path != "hid://two" {
		t.Fatalf("selected by alias path = %q, want hid://two", selected.Report().Path)
	}

	if _, err = SelectDevice(devices, ""); err == nil {
		t.Fatal("SelectDevice(empty,multiple) returned nil error")
	} else if !model.IsErrorCategory(err, model.ErrorInvalidOperation) {
		t.Fatalf("SelectDevice(empty,multiple) error = %v, want invalid-operation", err)
	}

	if _, err = SelectDevice(devices, "missing"); err == nil {
		t.Fatal("SelectDevice(missing) returned nil error")
	} else if !model.IsErrorCategory(err, model.ErrorInvalidState) {
		t.Fatalf("SelectDevice(missing) error = %v, want invalid-state", err)
	}

	selected, err = SelectDevice(devices[:1], "")
	if err != nil {
		t.Fatalf("SelectDevice(empty,single): %v", err)
	}
	if selected.Report().Path != "hid://one" {
		t.Fatalf("auto-selected path = %q, want hid://one", selected.Report().Path)
	}

	if _, err = SelectDevice(nil, ""); err == nil {
		t.Fatal("SelectDevice(empty list) returned nil error")
	} else if !model.IsErrorCategory(err, model.ErrorInvalidState) {
		t.Fatalf("SelectDevice(empty list) error = %v, want invalid-state", err)
	}
}

func TestOpenSessionRejectsZeroDevice(t *testing.T) {
	session, err := OpenSession(context.Background(), Device{})
	if !model.IsErrorCategory(err, model.ErrorInvalidOperation) {
		t.Fatalf("OpenSession error = %v, want invalid-operation", err)
	}

	if session != nil {
		t.Fatalf("session = %#v, want nil", session)
	}
}

func newFakeDiscoveryResolver(descriptors []transport.Descriptor) *fakeDiscoveryResolver {
	return &fakeDiscoveryResolver{
		resolved: transport.ResolvedProvider{
			Mode:     transport.ModeHID,
			Provider: &fakeDiscoveryProvider{list: descriptors},
		},
	}
}

func TestDiscoverDevicesMapsResolverErrors(t *testing.T) {
	resolver := &fakeDiscoveryResolver{err: transport.ErrUnsupportedMode}

	_, err := discoverDevices(context.Background(), resolver)
	if !model.IsErrorCategory(err, model.ErrorUnsupported) && !errors.Is(err, transport.ErrUnsupportedMode) {
		t.Fatalf("DiscoverDevices error = %v, want unsupported", err)
	}
}
