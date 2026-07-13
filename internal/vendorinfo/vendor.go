package vendorinfo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ctap/ctap/yubico"
	"github.com/go-ctap/kit/internal/authenticator"
	rtdevice "github.com/go-ctap/kit/internal/device"
	"github.com/go-ctap/kit/model/report"
)

const (
	yubicoVendorID uint16 = 0x1050
	token2VendorID uint16 = 0x349e
)

type yubicoInfoProvider interface {
	GetYubiKeyDeviceInfo(context.Context) (yubico.DeviceInfo, error)
}

func Classify(vendorID uint16) report.Vendor {
	switch vendorID {
	case yubicoVendorID:
		return report.VendorYubico
	case token2VendorID:
		return report.VendorToken2
	default:
		return report.VendorUnknown
	}
}

// CanProbe reports whether the current runtime has a metadata probe for device.
func CanProbe(device report.DeviceReport) bool {
	return device.Vendor == report.VendorYubico || device.Vendor == report.VendorToken2
}

func Enrich(ctx context.Context, device report.DeviceReport, authenticator any) (*report.DeviceMetadata, error) {
	switch device.Vendor {
	case report.VendorYubico:
		provider, ok := authenticator.(yubicoInfoProvider)
		if !ok {
			return nil, fmt.Errorf("ctapkit: Yubico device information is unsupported")
		}

		info, err := provider.GetYubiKeyDeviceInfo(ctx)
		if err != nil {
			return nil, err
		}

		return normalizeYubico(device, info), nil
	case report.VendorToken2, report.VendorUnknown:
		return nil, nil
	default:
		return nil, nil
	}
}

// EnrichOpen obtains metadata while the caller already owns the selected
// authenticator. Transport-independent vendor channels may still be used.
func EnrichOpen(
	ctx context.Context,
	device report.DeviceReport,
	authenticator any,
) (*report.DeviceMetadata, error) {
	if device.Vendor == report.VendorToken2 {
		return probeToken2(ctx, device, false)
	}

	return Enrich(ctx, device, authenticator)
}

// Probe acquires temporary ownership of a discovered device and obtains its
// vendor metadata without running a full CTAP inspection workflow.
func Probe(ctx context.Context, device report.DeviceReport) (*report.DeviceMetadata, error) {
	if !CanProbe(device) {
		return nil, nil
	}

	lease, err := rtdevice.AcquireLease(ctx, device)
	if err != nil {
		return nil, err
	}

	var metadata *report.DeviceMetadata
	var probeErr error
	switch device.Vendor {
	case report.VendorYubico:
		var auth authenticator.Device
		auth, probeErr = authenticator.Open(ctx, device.Transport, device.Path)
		if probeErr == nil {
			metadata, probeErr = Enrich(ctx, device, auth)
			probeErr = errors.Join(probeErr, auth.Close())
		}
	case report.VendorToken2:
		metadata, probeErr = probeToken2(ctx, device, true)
	}

	return metadata, errors.Join(probeErr, lease.Close())
}

func normalizeYubico(device report.DeviceReport, info yubico.DeviceInfo) *report.DeviceMetadata {
	metadata := &report.DeviceMetadata{
		Model: yubicoModelName(device.Product, info),
		Interfaces: []report.InterfaceReport{{
			Interface: report.InterfaceUSB,
			Supported: capabilities(info.SupportedUSBCapabilities),
			Enabled:   capabilities(info.EnabledUSBCapabilities),
		}},
	}
	if info.FirmwareVersion != (yubico.FirmwareVersion{}) {
		metadata.Firmware = strconv.Itoa(int(info.FirmwareVersion.Major)) + "." +
			strconv.Itoa(int(info.FirmwareVersion.Minor)) + "." +
			strconv.Itoa(int(info.FirmwareVersion.Build))
	}
	if info.Serial != nil {
		metadata.Serial = strconv.FormatUint(uint64(*info.Serial), 10)
	}
	if hasYubicoNFC(info) {
		var supported, enabled yubico.Capability
		if info.SupportedNFCCapabilities != nil {
			supported = *info.SupportedNFCCapabilities
		}
		if info.EnabledNFCCapabilities != nil {
			enabled = *info.EnabledNFCCapabilities
		}
		metadata.Interfaces = append(metadata.Interfaces, report.InterfaceReport{
			Interface: report.InterfaceNFC,
			Supported: capabilities(supported),
			Enabled:   capabilities(enabled),
		})
	}

	return metadata
}

func yubicoModelName(fallback string, info yubico.DeviceInfo) string {
	if isYubicoPreview(info.FirmwareVersion) {
		return "YubiKey Preview"
	}
	if !supportsYubicoDynamicName(info.FirmwareVersion) || info.FormFactor == yubico.FormFactorUnknown {
		return fallback
	}

	isNano := info.FormFactor == yubico.FormFactorUSBANano ||
		info.FormFactor == yubico.FormFactorUSBCNano
	isBio := info.FormFactor == yubico.FormFactorUSBABiometricKeychain ||
		info.FormFactor == yubico.FormFactorUSBCBiometricKeychain
	isUSBTypeC := info.FormFactor == yubico.FormFactorUSBCKeychain ||
		info.FormFactor == yubico.FormFactorUSBCNano ||
		info.FormFactor == yubico.FormFactorUSBCBiometricKeychain

	var parts []string
	if info.IsSecurityKey {
		parts = []string{"Security Key"}
	} else {
		parts = []string{"YubiKey"}
		if !isBio {
			parts = append(parts, "5")
		}
	}

	if isUSBTypeC {
		parts = append(parts, "C")
	} else if info.FormFactor == yubico.FormFactorUSBCLightning {
		parts = append(parts, "Ci")
	}

	if isNano {
		parts = append(parts, "Nano")
	} else if hasYubicoNFC(info) {
		parts = append(parts, "NFC")
	} else if info.FormFactor == yubico.FormFactorUSBAKeychain {
		parts = append(parts, "A")
	} else if isBio {
		parts = append(parts, "Bio")
	}

	if info.IsFIPS {
		parts = append(parts, "FIPS")
	} else if isBio {
		switch {
		case isFIDOOnly(info.SupportedUSBCapabilities):
			parts = append(parts, "- FIDO Edition")
		case info.SupportedUSBCapabilities&yubico.CapabilityPIV != 0:
			parts = append(parts, "- Multi-protocol Edition")
		}
	} else if info.IsSecurityKey && info.Serial != nil {
		parts = append(parts, "- Enterprise Edition")
	}

	name := strings.Join(parts, " ")
	name = strings.Replace(name, "5 C", "5C", 1)
	return strings.Replace(name, "5 A", "5A", 1)
}

func supportsYubicoDynamicName(version yubico.FirmwareVersion) bool {
	return version.Major == 5 && version.Minor >= 1
}

func isYubicoPreview(version yubico.FirmwareVersion) bool {
	ranges := [][2]yubico.FirmwareVersion{
		{{Major: 5}, {Major: 5, Minor: 1}},
		{{Major: 5, Minor: 2}, {Major: 5, Minor: 2, Build: 3}},
		{{Major: 5, Minor: 5}, {Major: 5, Minor: 5, Build: 2}},
	}
	for _, firmwareRange := range ranges {
		if firmwareAtLeast(version, firmwareRange[0]) && !firmwareAtLeast(version, firmwareRange[1]) {
			return true
		}
	}

	return false
}

func hasYubicoNFC(info yubico.DeviceInfo) bool {
	if info.SupportedNFCCapabilities == nil && info.EnabledNFCCapabilities == nil {
		return false
	}

	switch info.FormFactor {
	case yubico.FormFactorUSBANano,
		yubico.FormFactorUSBCNano,
		yubico.FormFactorUSBCLightning:
		return false
	case yubico.FormFactorUSBCKeychain:
		return firmwareAtLeast(info.FirmwareVersion, yubico.FirmwareVersion{Major: 5, Minor: 2, Build: 4})
	default:
		return true
	}
}

func firmwareAtLeast(got, want yubico.FirmwareVersion) bool {
	if got.Major != want.Major {
		return got.Major > want.Major
	}
	if got.Minor != want.Minor {
		return got.Minor > want.Minor
	}
	return got.Build >= want.Build
}

func isFIDOOnly(value yubico.Capability) bool {
	const capabilityHSMAuth yubico.Capability = 0x0100

	nonFIDO := yubico.CapabilityOTP |
		yubico.CapabilityOATH |
		yubico.CapabilityPIV |
		yubico.CapabilityOpenPGP |
		capabilityHSMAuth
	fido := yubico.CapabilityU2F | yubico.CapabilityCTAP2

	return value&nonFIDO == 0 && value&fido != 0
}

func capabilities(value yubico.Capability) []report.Capability {
	known := []struct {
		mask yubico.Capability
		name report.Capability
	}{
		{yubico.CapabilityOTP, report.CapabilityOTP},
		{yubico.CapabilityU2F, report.CapabilityU2F},
		{yubico.CapabilityCCID, report.CapabilityCCID},
		{yubico.CapabilityOpenPGP, report.CapabilityOpenPGP},
		{yubico.CapabilityPIV, report.CapabilityPIV},
		{yubico.CapabilityOATH, report.CapabilityOATH},
		{yubico.CapabilityCTAP2, report.CapabilityCTAP2},
	}

	result := make([]report.Capability, 0, len(known))
	for _, capability := range known {
		if value&capability.mask != 0 {
			result = append(result, capability.name)
		}
	}

	return result
}
