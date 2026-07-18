package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/model/failure"
	modelreport "github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

type fakeTransportDiscovery struct {
	mode      transport.Mode
	list      []transport.Descriptor
	err       error
	requested transport.Mode
}

func (d *fakeTransportDiscovery) discover(
	_ context.Context,
	requested transport.Mode,
) (transport.Mode, []transport.Descriptor, error) {
	d.requested = requested

	if d.err != nil {
		return "", nil, d.err
	}

	return d.mode, d.list, nil
}

func TestDiscoverDevicesReturnsOpaqueDevicesWithReports(t *testing.T) {
	discovery := newFakeTransportDiscovery([]transport.Descriptor{{
		Path:         "hid://one",
		Manufacturer: "Yubico",
		Product:      "YubiKey 5C NFC",
		Serial:       "12345678",
		VendorID:     0x1050,
		ProductID:    0x0407,
	}})

	devices, err := discoverDevices(context.Background(), discovery.discover, transport.ModeAuto)
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}

	if discovery.requested != transport.ModeAuto {
		t.Fatalf("requested mode = %q, want %q", discovery.requested, transport.ModeAuto)
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

	devices, err := discoverDevices(context.Background(), newFakeTransportDiscovery(descriptors).discover, transport.ModeAuto)
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}

	if first, second := devices[0].Report().Fingerprint, devices[1].Report().Fingerprint; first == second {
		t.Fatalf("fingerprints for different transport paths collide: %q", first)
	}

	descriptors[0].Path = "hid://renumbered"
	repeated, err := discoverDevices(context.Background(), newFakeTransportDiscovery(descriptors[:1]).discover, transport.ModeAuto)
	if err != nil {
		t.Fatalf("DiscoverDevices after path change: %v", err)
	}

	if got, previous := repeated[0].Report().Fingerprint, devices[0].Report().Fingerprint; got == previous {
		t.Fatalf("fingerprint did not change with transport path: %q", got)
	}
}

func TestDiscoverDevicesWithTransportPassesRequestedMode(t *testing.T) {
	discovery := newFakeTransportDiscovery([]transport.Descriptor{{
		Path:      "hid://one",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}})

	if _, err := discoverDevices(context.Background(), discovery.discover, transport.ModeHID); err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}

	if discovery.requested != transport.ModeHID {
		t.Fatalf("requested mode = %q, want %q", discovery.requested, transport.ModeHID)
	}
}

func TestSelectDeviceUsesDiscoverySnapshot(t *testing.T) {
	devices, err := discoverDevices(context.Background(), newFakeTransportDiscovery([]transport.Descriptor{
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
	}).discover, transport.ModeAuto)
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

func TestOpenAuthenticatorRejectsZeroDevice(t *testing.T) {
	session, err := OpenAuthenticator(context.Background(), Device{})
	requireFailureCode(t, err, failure.CodeDeviceHandleInvalid)

	if session != nil {
		t.Fatalf("session = %#v, want nil", session)
	}
}

func newFakeTransportDiscovery(descriptors []transport.Descriptor) *fakeTransportDiscovery {
	return &fakeTransportDiscovery{
		mode: transport.ModeHID,
		list: descriptors,
	}
}
