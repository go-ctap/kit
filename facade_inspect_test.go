package ctapkit

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/ctap/yubico"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func TestInspectEmitsNoEventsWithoutProgressOrStateChanges(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractAuthenticator(t, events, nil)
	defer func() { _ = session.Close() }()

	output, err := session.Inspect(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if output.Device.Fingerprint == "" {
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
	session := openYubicoContractAuthenticator(t, auth)
	defer func() { _ = session.Close() }()

	result, err := session.Inspect(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	metadata := result.Device.Metadata
	if metadata == nil || metadata.Model != "YubiKey 5C NFC" || metadata.Serial != "12345678" || metadata.Firmware != "5.7.1" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestInspectKeepsBaseResultWhenYubicoMetadataFails(t *testing.T) {
	auth := &yubicoContractAuthenticator{err: errors.New("vendor command failed")}
	session := openYubicoContractAuthenticator(t, auth)
	defer func() { _ = session.Close() }()

	result, err := session.Inspect(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	device := result.Device
	if device.Vendor != report.VendorYubico || device.Metadata != nil {
		t.Fatalf("device = %#v", device)
	}
}

type yubicoContractAuthenticator struct {
	contractAuthenticator
	info yubico.DeviceInfo
	err  error
}

func (a *yubicoContractAuthenticator) GetYubiKeyDeviceInfo(context.Context) (yubico.DeviceInfo, error) {
	return a.info, a.err
}

func openYubicoContractAuthenticator(t *testing.T, auth any) *contractAuthenticatorHandle {
	t.Helper()

	device := newDevice(0, transport.ModeHID, transport.Descriptor{
		Path:      "contract-yubico",
		Product:   "Yubico Authenticator",
		VendorID:  0x1050,
		ProductID: 0x0407,
	})
	session, err := openAuthenticatorHandle(
		context.Background(),
		device,
		func(context.Context, transport.Mode, string) (*authenticator.Opened, error) {
			return adaptContractAuthenticator(auth), nil
		},
	)
	if err != nil {
		t.Fatalf("OpenAuthenticator: %v", err)
	}

	return &contractAuthenticatorHandle{Authenticator: session}
}
