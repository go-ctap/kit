package identity

import (
	"reflect"
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/yubico"
)

func TestYubicoIdentityIncludesNormalizedDetails(t *testing.T) {
	partNumber := "5060405"
	fpsVersion := yubico.FirmwareVersion{Major: 1, Minor: 2, Build: 3}
	stmVersion := yubico.FirmwareVersion{Major: 4, Minor: 5, Build: 6}
	nfcSupported := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	nfcEnabled := yubico.CapabilityCTAP2
	info := yubico.DeviceInfo{
		SupportedUSBCapabilities: yubico.CapabilityOTP |
			yubico.CapabilityHSMAuth |
			yubico.CapabilityCTAP2,
		Serial:                 new(uint32(12345678)),
		EnabledUSBCapabilities: yubico.CapabilityHSMAuth | yubico.CapabilityCTAP2,
		FormFactor:             yubico.FormFactorUSBCKeychain,
		IsFIPS:                 true,
		FirmwareVersion: yubico.FirmwareVersion{
			Major: 5,
			Minor: 7,
			Build: 1,
		},
		VersionQualifier: &yubico.VersionQualifier{
			Version: yubico.FirmwareVersion{
				Major: 5,
				Minor: 8,
				Build: 0,
			},
			ReleaseType: yubico.ReleaseTypeBeta,
			Iteration:   3,
		},
		AutoEjectTimeout:         10,
		ChallengeResponseTimeout: 20,
		Locked:                   true,
		PartNumber:               &partNumber,
		FIPSCapable: yubico.CapabilityPIV |
			yubico.CapabilityHSMAuth |
			yubico.CapabilityCTAP2,
		FIPSApproved:             yubico.CapabilityPIV | yubico.CapabilityCTAP2,
		PinComplexity:            true,
		NFCRestricted:            true,
		ResetBlocked:             yubico.CapabilityU2F | yubico.CapabilityHSMAuth,
		FPSVersion:               &fpsVersion,
		STMVersion:               &stmVersion,
		SupportedNFCCapabilities: &nfcSupported,
		EnabledNFCCapabilities:   &nfcEnabled,
	}

	got := yubicoIdentity("fallback", info)
	want := &report.DeviceIdentity{
		Vendor:   report.VendorYubico,
		Model:    "YubiKey 5C NFC FIPS",
		Serial:   "12345678",
		Firmware: "5.7.1",
		Interfaces: []report.InterfaceReport{
			{
				Interface: report.InterfaceUSB,
				Supported: []report.Capability{
					report.CapabilityOTP,
					report.CapabilityHSMAuth,
					report.CapabilityCTAP2,
				},
				Enabled: []report.Capability{
					report.CapabilityHSMAuth,
					report.CapabilityCTAP2,
				},
			},
			{
				Interface: report.InterfaceNFC,
				Supported: []report.Capability{
					report.CapabilityU2F,
					report.CapabilityCTAP2,
				},
				Enabled: []report.Capability{
					report.CapabilityCTAP2,
				},
			},
		},
		Details: &report.VendorDetails{
			Yubico: &report.YubicoDetails{
				PartNumber:        "5060405",
				FormFactor:        report.YubicoFormFactorUSBCKeychain,
				IsFIPS:            true,
				EffectiveFirmware: "5.8.0",
				VersionQualifier: &report.YubicoVersionQualifier{
					Version:     "5.8.0",
					ReleaseType: report.YubicoReleaseTypeBeta,
					Iteration:   3,
				},
				AutoEjectTimeout:         10,
				ChallengeResponseTimeout: 20,
				Locked:                   true,
				FIPSCapable: []report.Capability{
					report.CapabilityPIV,
					report.CapabilityHSMAuth,
					report.CapabilityCTAP2,
				},
				FIPSApproved: []report.Capability{
					report.CapabilityPIV,
					report.CapabilityCTAP2,
				},
				PINComplexity: true,
				NFCRestricted: true,
				ResetBlocked: []report.Capability{
					report.CapabilityU2F,
					report.CapabilityHSMAuth,
				},
				FPSVersion: "1.2.3",
				STMVersion: "4.5.6",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("yubicoIdentity() = %#v, want %#v", got, want)
	}
}

func TestYubicoCapabilitiesIncludesEveryKnownApplication(t *testing.T) {
	value := yubico.CapabilityOTP |
		yubico.CapabilityU2F |
		yubico.CapabilityCCID |
		yubico.CapabilityOpenPGP |
		yubico.CapabilityPIV |
		yubico.CapabilityOATH |
		yubico.CapabilityHSMAuth |
		yubico.CapabilityCTAP2

	got := yubicoCapabilities(value)
	want := []report.Capability{
		report.CapabilityOTP,
		report.CapabilityU2F,
		report.CapabilityCCID,
		report.CapabilityOpenPGP,
		report.CapabilityPIV,
		report.CapabilityOATH,
		report.CapabilityHSMAuth,
		report.CapabilityCTAP2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("yubicoCapabilities() = %v, want %v", got, want)
	}
}

func TestYubicoFormFactorMapping(t *testing.T) {
	tests := []struct {
		input yubico.FormFactor
		want  report.YubicoFormFactor
	}{
		{input: yubico.FormFactorUnknown, want: report.YubicoFormFactorUnknown},
		{input: yubico.FormFactorUSBAKeychain, want: report.YubicoFormFactorUSBAKeychain},
		{input: yubico.FormFactorUSBANano, want: report.YubicoFormFactorUSBANano},
		{input: yubico.FormFactorUSBCKeychain, want: report.YubicoFormFactorUSBCKeychain},
		{input: yubico.FormFactorUSBCNano, want: report.YubicoFormFactorUSBCNano},
		{input: yubico.FormFactorUSBCLightning, want: report.YubicoFormFactorUSBCLightning},
		{
			input: yubico.FormFactorUSBABiometricKeychain,
			want:  report.YubicoFormFactorUSBABiometricKeychain,
		},
		{
			input: yubico.FormFactorUSBCBiometricKeychain,
			want:  report.YubicoFormFactorUSBCBiometricKeychain,
		},
		{input: yubico.FormFactor(0xff), want: report.YubicoFormFactorUnknown},
	}

	for _, test := range tests {
		if got := yubicoFormFactor(test.input); got != test.want {
			t.Errorf("yubicoFormFactor(%d) = %q, want %q", test.input, got, test.want)
		}
	}
}
