package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func TestDeviceMetadataCacheRoundTrip(t *testing.T) {
	cacheDir := t.TempDir()
	metadata := report.DeviceMetadata{
		Model:    "YubiKey 5",
		Serial:   "1234567",
		Firmware: "5.7.4",
		Interfaces: []report.InterfaceReport{{
			Interface: report.InterfaceUSB,
			Enabled:   []report.Capability{report.CapabilityCTAP2},
		}},
	}

	if err := writeDeviceMetadata(cacheDir, "fingerprint-1", metadata); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	path := filepath.Join(cacheDir, "fingerprint-1", "info.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	cached, ok := readDeviceMetadata(cacheDir, "fingerprint-1")
	if !ok || !deviceMetadataEqual(cached, metadata) {
		t.Fatalf("cached metadata = %#v, ok = %v", cached, ok)
	}
}

func TestRestoredDeviceMetadataSkipsProbe(t *testing.T) {
	service := New()
	service.deviceMetadataCacheDir = t.TempDir()
	device := report.DeviceReport{
		Fingerprint: "fingerprint-1",
		Transport:   transport.ModeHID,
		Vendor:      report.VendorYubico,
	}
	metadata := report.DeviceMetadata{Model: "YubiKey 5"}
	if err := writeDeviceMetadata(service.deviceMetadataCacheDir, device.Fingerprint, metadata); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	service.restoreDeviceMetadata([]report.DeviceReport{device})
	if candidate, ok := takeEnrichmentCandidate(
		[]report.DeviceReport{device},
		service.enrichment.cache,
		make(map[string]struct{}),
	); ok {
		t.Fatalf("cached device selected for probe: %#v", candidate)
	}
}

func TestDeviceMetadataCacheRejectsUnsafeFingerprint(t *testing.T) {
	cacheDir := t.TempDir()
	if err := writeDeviceMetadata(cacheDir, "../outside", report.DeviceMetadata{Model: "unsafe"}); err != nil {
		t.Fatalf("write unsafe fingerprint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "outside", "info.json")); !os.IsNotExist(err) {
		t.Fatalf("unsafe cache path exists or stat failed unexpectedly: %v", err)
	}
}

func TestTakeEnrichmentCandidateAttemptsAvailableKnownVendors(t *testing.T) {
	cache := make(map[string]report.DeviceMetadata)
	attempted := make(map[string]struct{})
	devices := []report.DeviceReport{
		{Fingerprint: "unknown", Vendor: report.VendorUnknown},
		{Fingerprint: "token2", Vendor: report.VendorToken2},
		{Fingerprint: "busy", Vendor: report.VendorYubico},
		{Fingerprint: "ready", Vendor: report.VendorYubico},
	}

	first, ok := takeEnrichmentCandidate(devices, cache, attempted)
	if !ok || first.Fingerprint != "token2" {
		t.Fatalf("first candidate = %#v, ok = %v", first, ok)
	}
	second, ok := takeEnrichmentCandidate(devices, cache, attempted)
	if !ok || second.Fingerprint != "busy" {
		t.Fatalf("second candidate = %#v, ok = %v", second, ok)
	}
	if _, ok := attempted[enrichmentKey(first)]; !ok {
		t.Fatal("first candidate was not marked attempted")
	}
	if _, ok := attempted[enrichmentKey(second)]; !ok {
		t.Fatal("second candidate was not marked attempted")
	}

	if third, ok := takeEnrichmentCandidate(devices, cache, attempted); !ok || third.Fingerprint != "ready" {
		t.Fatalf("third candidate = %#v, ok = %v", third, ok)
	}
	if _, ok := takeEnrichmentCandidate(devices, cache, attempted); ok {
		t.Fatal("already attempted device was selected again")
	}
	if got, ok := takeEnrichmentCandidate(devices, cache, make(map[string]struct{})); !ok || got.Fingerprint != "token2" {
		t.Fatalf("new pass candidate = %#v, ok = %v", got, ok)
	}
}

func TestCloneDeviceMetadataCopiesCapabilitySlices(t *testing.T) {
	original := report.DeviceMetadata{
		Model: "YubiKey",
		Interfaces: []report.InterfaceReport{{
			Interface: report.InterfaceUSB,
			Supported: []report.Capability{report.CapabilityU2F},
			Enabled:   []report.Capability{report.CapabilityCTAP2},
		}},
	}

	clone := cloneDeviceMetadata(original)
	clone.Interfaces[0].Supported[0] = report.CapabilityOTP
	clone.Interfaces[0].Enabled[0] = report.CapabilityCCID

	if original.Interfaces[0].Supported[0] != report.CapabilityU2F ||
		original.Interfaces[0].Enabled[0] != report.CapabilityCTAP2 {
		t.Fatalf("clone mutated original: %#v", original)
	}
}

func TestEnrichmentKeyIncludesTransport(t *testing.T) {
	hid := enrichmentKey(report.DeviceReport{Fingerprint: "fingerprint", Transport: transport.ModeHID})
	proxy := enrichmentKey(report.DeviceReport{Fingerprint: "fingerprint", Transport: transport.ModeWindowsProxy})
	if hid == proxy {
		t.Fatalf("keys collide: %q", hid)
	}
}

func TestDeviceReportsEqualComparesMetadataValues(t *testing.T) {
	first := []report.DeviceReport{{
		Fingerprint: "fingerprint",
		Metadata: &report.DeviceMetadata{
			Model: "YubiKey",
			Interfaces: []report.InterfaceReport{{
				Interface: report.InterfaceUSB,
				Enabled:   []report.Capability{report.CapabilityCTAP2},
			}},
		},
	}}
	second := []report.DeviceReport{{
		Fingerprint: "fingerprint",
		Metadata: &report.DeviceMetadata{
			Model: "YubiKey",
			Interfaces: []report.InterfaceReport{{
				Interface: report.InterfaceUSB,
				Enabled:   []report.Capability{report.CapabilityCTAP2},
			}},
		},
	}}

	if !deviceReportsEqual(first, second) {
		t.Fatal("equal reports were treated as changed")
	}
	second[0].Metadata.Interfaces[0].Enabled[0] = report.CapabilityU2F
	if deviceReportsEqual(first, second) {
		t.Fatal("different metadata was treated as equal")
	}
}
