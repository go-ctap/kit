package ctapkit

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/ctap/yubico"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func TestInspectEmitsNoEventsWithoutProgressOrStateChanges(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractSession(t, events, nil)
	defer func() { _ = session.Close() }()

	output, err := session.Run(context.Background(), model.InspectOperation{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := output.(model.InspectOutput); !ok {
		t.Fatalf("unexpected output: %#v", output)
	}

	recorded := events.Events()
	if len(recorded) != 0 {
		t.Fatalf("events = %v, want none", recorded)
	}
}

func TestInspectNormalizesYubicoMetadata(t *testing.T) {
	serial := uint32(12345678)
	supportedNFC := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	auth := &yubicoContractAuthenticator{info: yubico.DeviceInfo{
		Serial:                   &serial,
		FormFactor:               yubico.FormFactorUSBCKeychain,
		FirmwareVersion:          yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1},
		SupportedUSBCapabilities: yubico.CapabilityU2F | yubico.CapabilityCTAP2,
		EnabledUSBCapabilities:   yubico.CapabilityCTAP2,
		SupportedNFCCapabilities: &supportedNFC,
	}}
	session := openYubicoContractSession(t, auth)
	defer func() { _ = session.Close() }()

	result, err := session.Run(context.Background(), model.InspectOperation{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	metadata := result.(model.InspectOutput).Result.Device.Metadata
	if metadata == nil || metadata.Model != "YubiKey 5C NFC" || metadata.Serial != "12345678" || metadata.Firmware != "5.7.1" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestInspectKeepsBaseResultWhenYubicoMetadataFails(t *testing.T) {
	auth := &yubicoContractAuthenticator{err: errors.New("vendor command failed")}
	session := openYubicoContractSession(t, auth)
	defer func() { _ = session.Close() }()

	result, err := session.Run(context.Background(), model.InspectOperation{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	device := result.(model.InspectOutput).Result.Device
	if device.Vendor != report.VendorYubico || device.Metadata != nil {
		t.Fatalf("device = %#v", device)
	}
}

type yubicoContractAuthenticator struct {
	contractAuthenticator
	info yubico.DeviceInfo
	err  error
}

func (a *yubicoContractAuthenticator) GetYubiKeyDeviceInfo() (yubico.DeviceInfo, error) {
	return a.info, a.err
}

func openYubicoContractSession(t *testing.T, auth authenticator.Device) *Session {
	t.Helper()

	device := newDevice(0, transport.ModeHID, transport.Descriptor{
		Path:      "contract-yubico",
		Product:   "Yubico Authenticator",
		VendorID:  0x1050,
		ProductID: 0x0407,
	})
	session, err := openSession(context.Background(), device, newContractSessionDependencies(
		func(context.Context, transport.Mode, string) (authenticator.Device, error) {
			return auth, nil
		},
	))
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	return session
}
