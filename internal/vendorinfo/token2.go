package vendorinfo

import (
	"context"
	"slices"
	"strings"

	ghid "github.com/go-ctap/hid"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
	nativepcsc "github.com/go-ctap/pcsc"
	"github.com/go-ctap/token2"
	token2ctaphid "github.com/go-ctap/token2/transport/ctaphid"
	token2hid "github.com/go-ctap/token2/transport/hid"
	token2pcsc "github.com/go-ctap/token2/transport/pcsc"
)

const (
	fidoUsagePage uint16 = 0xf1d0
	fidoUsage     uint16 = 0x01
)

type token2Candidate struct {
	metadata report.DeviceMetadata
}

func probeToken2(
	ctx context.Context,
	device report.DeviceReport,
	allowCTAPHID bool,
) (*report.DeviceMetadata, error) {
	// PC/SC is the primary source because it exposes the full serial, model
	// identity, and configuration even when Token2's optional feature HID is
	// disabled. CTAPHID is used only to disambiguate matching PC/SC readers.
	candidates := token2PCSCCandidates(ctx, device.ProductID)
	if metadata, ok := selectToken2Candidate(candidates, device.Serial, ""); ok {
		return &metadata, nil
	}

	if allowCTAPHID && len(candidates) > 1 && device.Transport == transport.ModeHID {
		if suffix := token2CTAPHIDSerialSuffix(ctx, device.Path); suffix != "" {
			if metadata, ok := selectToken2Candidate(candidates, "", suffix); ok {
				return &metadata, nil
			}
		}
	}

	if metadata, ok := token2FeatureHIDMetadata(ctx, device); ok {
		return &metadata, nil
	}

	return nil, nil
}

func token2PCSCCandidates(ctx context.Context, productID uint16) []token2Candidate {
	var candidates []token2Candidate
	for reader, err := range nativepcsc.Enumerate() {
		if err != nil || ctx.Err() != nil {
			break
		}

		device, err := token2pcsc.Open(reader.Name)
		if err != nil {
			continue
		}

		atr, atrErr := device.ATRInfo()
		if atrErr != nil || atr.ProductID != productID {
			_ = device.Close()
			continue
		}

		serialNumber, serialErr := device.SerialNumber()
		config, configErr := device.Config()
		_ = device.Close()
		if serialErr != nil {
			continue
		}

		metadata := token2IdentityMetadata(serialNumber)
		if configErr == nil {
			addToken2Config(&metadata, config)
		}
		candidates = append(candidates, token2Candidate{metadata: metadata})
	}

	return deduplicateToken2Candidates(candidates)
}

func token2CTAPHIDSerialSuffix(ctx context.Context, path string) string {
	if ctx.Err() != nil {
		return ""
	}

	device, err := token2ctaphid.Open(path)
	if err != nil {
		return ""
	}

	info, infoErr := device.ATRInfo()
	_ = device.Close()
	if infoErr != nil {
		return ""
	}

	return info.SerialSuffix
}

func token2FeatureHIDMetadata(
	ctx context.Context,
	selected report.DeviceReport,
) (report.DeviceMetadata, bool) {
	if selected.Transport != transport.ModeHID {
		return report.DeviceMetadata{}, false
	}

	var candidates []token2Candidate
	for info, err := range ghid.Enumerate(
		ghid.WithVendorID(token2VendorID),
		ghid.WithProductID(selected.ProductID),
	) {
		if err != nil || ctx.Err() != nil {
			break
		}
		if info.Path == selected.Path || info.UsagePage == fidoUsagePage && info.Usage == fidoUsage {
			continue
		}

		device, err := token2hid.Open(info.Path)
		if err != nil {
			continue
		}
		serialNumber, serialErr := device.SerialNumber()
		_ = device.Close()
		if serialErr != nil {
			continue
		}

		candidates = append(candidates, token2Candidate{
			metadata: token2IdentityMetadata(serialNumber),
		})
	}

	candidates = deduplicateToken2Candidates(candidates)
	return selectToken2Candidate(candidates, selected.Serial, "")
}

func token2IdentityMetadata(serialNumber string) report.DeviceMetadata {
	metadata := report.DeviceMetadata{Serial: serialNumber}
	if identity, ok := token2.Identify(serialNumber); ok {
		metadata.Model = normalizedToken2ModelName(identity.Model)
		metadata.Firmware = strings.TrimSpace(identity.Model.Revision)
	}

	return metadata
}

func normalizedToken2ModelName(model token2.Model) string {
	if strings.EqualFold(strings.TrimSpace(model.Branding), "unbranded") {
		model.Branding = ""
	}

	return model.DisplayName()
}

func addToken2Config(metadata *report.DeviceMetadata, config token2.Config) {
	if len(config.Raw) <= 1 {
		return
	}

	supported := make([]report.Capability, 0, 3)
	if config.HOTPSupported() || config.TOTPSupported() {
		supported = append(supported, report.CapabilityOTP)
	}
	if config.CCIDSupported() {
		supported = append(supported, report.CapabilityCCID)
	}
	if config.FIDO21Supported() {
		supported = append(supported, report.CapabilityCTAP2)
	}
	metadata.Interfaces = append(metadata.Interfaces, report.InterfaceReport{
		Interface: report.InterfaceUSB,
		Supported: supported,
	})
	if config.NFCSupported() {
		metadata.Interfaces = append(metadata.Interfaces, report.InterfaceReport{
			Interface: report.InterfaceNFC,
		})
	}
}

func selectToken2Candidate(
	candidates []token2Candidate,
	serialNumber string,
	serialSuffix string,
) (report.DeviceMetadata, bool) {
	if serialNumber != "" {
		for _, candidate := range candidates {
			if candidate.metadata.Serial == serialNumber {
				return candidate.metadata, true
			}
		}

		return report.DeviceMetadata{}, false
	}
	if len(candidates) == 1 {
		return candidates[0].metadata, true
	}
	if serialSuffix != "" {
		matched := slices.DeleteFunc(slices.Clone(candidates), func(candidate token2Candidate) bool {
			return !strings.HasSuffix(candidate.metadata.Serial, serialSuffix)
		})
		if len(matched) == 1 {
			return matched[0].metadata, true
		}
	}

	return report.DeviceMetadata{}, false
}

func deduplicateToken2Candidates(candidates []token2Candidate) []token2Candidate {
	seen := make(map[string]struct{}, len(candidates))
	return slices.DeleteFunc(candidates, func(candidate token2Candidate) bool {
		if _, ok := seen[candidate.metadata.Serial]; ok {
			return true
		}
		seen[candidate.metadata.Serial] = struct{}{}

		return false
	})
}
