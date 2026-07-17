package service

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func TestSessionClaimsArePerDevice(t *testing.T) {
	service := New()
	claimedDevice := report.DeviceReport{Fingerprint: "claimed", Transport: transport.ModeHID}
	otherDevice := report.DeviceReport{Fingerprint: "other", Transport: transport.ModeHID}
	service.enrichment.claims[enrichmentKey(claimedDevice)] = make(chan struct{})

	release, err := service.claimDeviceForSession(t.Context(), otherDevice)
	if err != nil {
		t.Fatalf("claim other device: %v", err)
	}
	release()

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if release, err := service.claimDeviceForSession(canceled, claimedDevice); err == nil {
		release()
		t.Fatal("claimed device was acquired")
	}

	service.releaseDeviceClaim(claimedDevice)
	release, err = service.claimDeviceForSession(t.Context(), claimedDevice)
	if err != nil {
		t.Fatalf("claim released device: %v", err)
	}
	release()
}

func TestTakeEnrichmentCandidateAttemptsAvailableKnownVendors(t *testing.T) {
	cache := make(map[string]report.DeviceMetadata)
	attempted := make(map[string]struct{})
	busyFingerprint := "busy"
	devices := []report.DeviceReport{
		{Fingerprint: "unknown", Vendor: report.VendorUnknown},
		{Fingerprint: "token2", Vendor: report.VendorToken2},
		{Fingerprint: busyFingerprint, Vendor: report.VendorYubico},
		{Fingerprint: "ready", Vendor: report.VendorYubico},
	}

	busy := func(device report.DeviceReport) bool {
		return device.Fingerprint == busyFingerprint
	}
	first, ok := takeEnrichmentCandidate(devices, cache, attempted, busy)
	if !ok || first.Fingerprint != "token2" {
		t.Fatalf("first candidate = %#v, ok = %v", first, ok)
	}
	second, ok := takeEnrichmentCandidate(devices, cache, attempted, busy)
	if !ok || second.Fingerprint != "ready" {
		t.Fatalf("second candidate = %#v, ok = %v", second, ok)
	}
	if _, ok := attempted[enrichmentKey(first)]; !ok {
		t.Fatal("first candidate was not marked attempted")
	}
	if _, ok := attempted[enrichmentKey(second)]; !ok {
		t.Fatal("second candidate was not marked attempted")
	}

	if _, ok := takeEnrichmentCandidate(devices, cache, attempted, busy); ok {
		t.Fatal("already attempted device was selected again")
	}
	if got, ok := takeEnrichmentCandidate(devices, cache, make(map[string]struct{}), busy); !ok || got.Fingerprint != "token2" {
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
