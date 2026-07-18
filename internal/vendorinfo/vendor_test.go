package vendorinfo

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/ctap/yubico"
	"github.com/go-ctap/kit/model/report"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		vendorID uint16
		want     report.Vendor
	}{
		{vendorID: 0x1050, want: report.VendorYubico},
		{vendorID: 0x349e, want: report.VendorToken2},
		{vendorID: 0xffff, want: report.VendorUnknown},
	}

	for _, test := range tests {
		if got := Classify(test.vendorID); got != test.want {
			t.Fatalf("Classify(%#04x) = %q, want %q", test.vendorID, got, test.want)
		}
	}
}

func TestCanProbe(t *testing.T) {
	if !CanProbe(report.DeviceReport{Vendor: report.VendorYubico}) {
		t.Fatal("Yubico probe is unavailable")
	}

	if !CanProbe(report.DeviceReport{Vendor: report.VendorToken2}) {
		t.Fatal("Token2 probe is unavailable")
	}
}

func TestEnrichYubicoNormalizesMetadata(t *testing.T) {
	serial := uint32(12345678)
	supportedNFC := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	enabledNFC := yubico.CapabilityCTAP2
	provider := &fakeYubicoProvider{info: yubico.DeviceInfo{
		SupportedUSBCapabilities: yubico.CapabilityOTP | yubico.CapabilityCCID | yubico.CapabilityCTAP2,
		EnabledUSBCapabilities:   yubico.CapabilityCCID | yubico.CapabilityCTAP2,
		Serial:                   &serial,
		FormFactor:               yubico.FormFactorUSBCKeychain,
		FirmwareVersion:          yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1},
		SupportedNFCCapabilities: &supportedNFC,
		EnabledNFCCapabilities:   &enabledNFC,
	}}

	metadata, err := Enrich(context.Background(), report.DeviceReport{
		Vendor:  report.VendorYubico,
		Product: "YubiKey 5C NFC",
	}, provider)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if metadata.Model != "YubiKey 5C NFC" || metadata.Serial != "12345678" || metadata.Firmware != "5.7.1" {
		t.Fatalf("metadata = %#v", metadata)
	}

	if len(metadata.Interfaces) != 2 {
		t.Fatalf("interfaces = %#v", metadata.Interfaces)
	}
	assertCapabilities(t, metadata.Interfaces[0].Supported, []report.Capability{
		report.CapabilityOTP,
		report.CapabilityCCID,
		report.CapabilityCTAP2,
	})
	assertCapabilities(t, metadata.Interfaces[0].Enabled, []report.Capability{
		report.CapabilityCCID,
		report.CapabilityCTAP2,
	})
	assertCapabilities(t, metadata.Interfaces[1].Supported, []report.Capability{
		report.CapabilityU2F,
		report.CapabilityCTAP2,
	})
	assertCapabilities(t, metadata.Interfaces[1].Enabled, []report.Capability{report.CapabilityCTAP2})
}

func TestEnrichYubicoPropagatesContext(t *testing.T) {
	type contextKey struct{}

	marker := new(int)
	ctx := context.WithValue(context.Background(), contextKey{}, marker)
	provider := &fakeYubicoProvider{}
	if _, err := Enrich(ctx, report.DeviceReport{Vendor: report.VendorYubico}, provider); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got := provider.ctx.Value(contextKey{}); got != marker {
		t.Fatalf("provider context value = %v, want marker", got)
	}
}

func TestYubicoModelName(t *testing.T) {
	nfc := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	serial := uint32(12345678)
	version := yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1}
	tests := []struct {
		name string
		info yubico.DeviceInfo
		want string
	}{
		{
			name: "USB-C nano",
			info: yubico.DeviceInfo{FirmwareVersion: version, FormFactor: yubico.FormFactorUSBCNano},
			want: "YubiKey 5C Nano",
		},
		{
			name: "USB-C NFC",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBCKeychain,
				SupportedNFCCapabilities: &nfc,
			},
			want: "YubiKey 5C NFC",
		},
		{
			name: "USB-A NFC",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBAKeychain,
				SupportedNFCCapabilities: &nfc,
			},
			want: "YubiKey 5 NFC",
		},
		{
			name: "USB-A without NFC",
			info: yubico.DeviceInfo{FirmwareVersion: version, FormFactor: yubico.FormFactorUSBAKeychain},
			want: "YubiKey 5A",
		},
		{
			name: "USB-C and Lightning",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBCLightning,
				SupportedNFCCapabilities: &nfc,
			},
			want: "YubiKey 5Ci",
		},
		{
			name: "USB-C keychain ignores invalid NFC before 5.2.4",
			info: yubico.DeviceInfo{
				FirmwareVersion:          yubico.FirmwareVersion{Major: 5, Minor: 2, Build: 3},
				FormFactor:               yubico.FormFactorUSBCKeychain,
				SupportedNFCCapabilities: &nfc,
			},
			want: "YubiKey 5C",
		},
		{
			name: "USB-C keychain accepts NFC from 5.2.4",
			info: yubico.DeviceInfo{
				FirmwareVersion:          yubico.FirmwareVersion{Major: 5, Minor: 2, Build: 4},
				FormFactor:               yubico.FormFactorUSBCKeychain,
				SupportedNFCCapabilities: &nfc,
			},
			want: "YubiKey 5C NFC",
		},
		{
			name: "Security Key USB-C NFC",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBCKeychain,
				IsSecurityKey:            true,
				SupportedNFCCapabilities: &nfc,
			},
			want: "Security Key C NFC",
		},
		{
			name: "Security Key Enterprise Edition",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBCKeychain,
				IsSecurityKey:            true,
				Serial:                   &serial,
				SupportedNFCCapabilities: &nfc,
			},
			want: "Security Key C NFC - Enterprise Edition",
		},
		{
			name: "FIPS",
			info: yubico.DeviceInfo{
				FirmwareVersion: version,
				FormFactor:      yubico.FormFactorUSBCNano,
				IsFIPS:          true,
			},
			want: "YubiKey 5C Nano FIPS",
		},
		{
			name: "USB-A Bio FIDO Edition",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBABiometricKeychain,
				SupportedUSBCapabilities: yubico.CapabilityU2F | yubico.CapabilityCTAP2,
			},
			want: "YubiKey Bio - FIDO Edition",
		},
		{
			name: "USB-C Bio Multi-protocol Edition",
			info: yubico.DeviceInfo{
				FirmwareVersion:          version,
				FormFactor:               yubico.FormFactorUSBCBiometricKeychain,
				SupportedUSBCapabilities: yubico.CapabilityU2F | yubico.CapabilityCTAP2 | yubico.CapabilityPIV,
			},
			want: "YubiKey C Bio - Multi-protocol Edition",
		},
		{
			name: "unknown form factor",
			info: yubico.DeviceInfo{FirmwareVersion: version, FormFactor: yubico.FormFactorUnknown},
			want: "USB product fallback",
		},
		{
			name: "preview firmware 5.0",
			info: yubico.DeviceInfo{
				FirmwareVersion: yubico.FirmwareVersion{Major: 5, Minor: 0, Build: 0},
				FormFactor:      yubico.FormFactorUSBCNano,
			},
			want: "YubiKey Preview",
		},
		{
			name: "preview firmware 5.2.2",
			info: yubico.DeviceInfo{
				FirmwareVersion: yubico.FirmwareVersion{Major: 5, Minor: 2, Build: 2},
				FormFactor:      yubico.FormFactorUSBCNano,
			},
			want: "YubiKey Preview",
		},
		{
			name: "preview firmware 5.5.1",
			info: yubico.DeviceInfo{
				FirmwareVersion: yubico.FirmwareVersion{Major: 5, Minor: 5, Build: 1},
				FormFactor:      yubico.FormFactorUSBCNano,
			},
			want: "YubiKey Preview",
		},
		{
			name: "production firmware 5.5.2",
			info: yubico.DeviceInfo{
				FirmwareVersion: yubico.FirmwareVersion{Major: 5, Minor: 5, Build: 2},
				FormFactor:      yubico.FormFactorUSBCNano,
			},
			want: "YubiKey 5C Nano",
		},
		{
			name: "unsupported firmware",
			info: yubico.DeviceInfo{
				FirmwareVersion: yubico.FirmwareVersion{Major: 4, Minor: 4, Build: 5},
				FormFactor:      yubico.FormFactorUSBCNano,
			},
			want: "USB product fallback",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := yubicoModelName("USB product fallback", test.info); got != test.want {
				t.Fatalf("yubicoModelName() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEnrichYubicoIgnoresKnownInvalidNFCMetadata(t *testing.T) {
	nfc := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	provider := &fakeYubicoProvider{info: yubico.DeviceInfo{
		FirmwareVersion:          yubico.FirmwareVersion{Major: 5, Minor: 2, Build: 3},
		FormFactor:               yubico.FormFactorUSBCKeychain,
		SupportedNFCCapabilities: &nfc,
		EnabledNFCCapabilities:   &nfc,
	}}

	metadata, err := Enrich(context.Background(), report.DeviceReport{
		Vendor:  report.VendorYubico,
		Product: "Yubico Authenticator",
	}, provider)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if metadata.Model != "YubiKey 5C" || len(metadata.Interfaces) != 1 {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestEnrichDoesNotCallToken2Provider(t *testing.T) {
	provider := &fakeYubicoProvider{err: errors.New("unexpected call")}

	metadata, err := Enrich(context.Background(), report.DeviceReport{Vendor: report.VendorToken2}, provider)
	if err != nil || metadata != nil || provider.called {
		t.Fatalf("metadata = %#v, err = %v, called = %v", metadata, err, provider.called)
	}
}

type fakeYubicoProvider struct {
	info   yubico.DeviceInfo
	err    error
	called bool
	ctx    context.Context
}

func (p *fakeYubicoProvider) GetYubiKeyDeviceInfo(ctx context.Context) (yubico.DeviceInfo, error) {
	p.called = true
	p.ctx = ctx

	return p.info, p.err
}

func assertCapabilities(t *testing.T, got, want []report.Capability) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("capabilities = %v, want %v", got, want)
		}
	}
}
