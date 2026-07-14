package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/model/failure"
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
	if report.Fingerprint == "" || report.OrdinalAlias != "1" || report.Transport != transport.ModeHID || report.Path != "hid://one" || report.Manufacturer != "Yubico" || report.Product != "YubiKey 5C NFC" || report.Serial != "12345678" || report.VendorID != 0x1050 || report.ProductID != 0x0407 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Vendor != modelreport.VendorYubico {
		t.Fatalf("vendor = %q, want %q", report.Vendor, modelreport.VendorYubico)
	}
}

func TestDiscoverDevicesFingerprintTracksTransportAttachment(t *testing.T) {
	descriptors := []transport.Descriptor{
		{
			Path:      "hid://one",
			Serial:    "duplicate",
			VendorID:  0x1050,
			ProductID: 0x0407,
		},
		{
			Path:      "hid://two",
			Serial:    "duplicate",
			VendorID:  0x1050,
			ProductID: 0x0407,
		},
	}

	devices, err := discoverDevices(context.Background(), newFakeDiscoveryResolver(descriptors))
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}
	if first, second := devices[0].Report().Fingerprint, devices[1].Report().Fingerprint; first == second {
		t.Fatalf("fingerprints for different transport paths collide: %q", first)
	}

	descriptors[0].Path = "hid://renumbered"
	repeated, err := discoverDevices(context.Background(), newFakeDiscoveryResolver(descriptors[:1]))
	if err != nil {
		t.Fatalf("DiscoverDevices after path change: %v", err)
	}
	if got, previous := repeated[0].Report().Fingerprint, devices[0].Report().Fingerprint; got == previous {
		t.Fatalf("fingerprint did not change with transport path: %q", got)
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

	selected, err := SelectDevice(devices, devices[0].Report().Fingerprint)
	if err != nil {
		t.Fatalf("SelectDevice(fingerprint): %v", err)
	}
	if selected.Report().Path != "hid://one" {
		t.Fatalf("selected by fingerprint path = %q, want hid://one", selected.Report().Path)
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
	} else {
		requireFailureCode(t, err, failure.CodeDeviceSelectionRequired)
	}

	if _, err = SelectDevice(devices, "missing"); err == nil {
		t.Fatal("SelectDevice(missing) returned nil error")
	} else {
		requireFailureCode(t, err, failure.CodeDeviceNotFound)
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
	} else {
		requireFailureCode(t, err, failure.CodeDeviceUnavailable)
	}
}

func TestOpenSessionRejectsZeroDevice(t *testing.T) {
	session, err := OpenSession(context.Background(), Device{})
	requireFailureCode(t, err, failure.CodeDeviceHandleInvalid)

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
