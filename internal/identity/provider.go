package identity

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/discovery"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
	token2resolver "github.com/go-ctap/token2/resolver"
	token2ctaphid "github.com/go-ctap/token2/transport/ctaphid"
	"github.com/go-ctap/yubico"
	yubicoresolver "github.com/go-ctap/yubico/resolver"
	yubicoctaphid "github.com/go-ctap/yubico/transport/ctaphid"
)

const (
	yubicoVendorID uint16 = 0x1050
	token2VendorID uint16 = 0x349e
)

// Resolver owns the built-in vendor identity providers. It returns one atomic
// identity and never merges results from multiple providers.
type Resolver struct {
	token2 token2IdentityResolver
	yubico yubicoIdentityResolver
	open   func(context.Context, transport.Mode, string) (*authenticator.Opened, error)
}

type token2IdentityResolver interface {
	ResolveSmartCard(context.Context, string) (token2resolver.Result, error)
	ResolveHID(context.Context, token2resolver.HIDTarget) (token2resolver.Result, error)
}

type yubicoIdentityResolver interface {
	ResolveSmartCard(context.Context, string) (yubico.DeviceInfo, error)
}

// Resolution is the complete successful outcome of resolving one descriptor.
type Resolution struct {
	Identity *report.DeviceIdentity
	Provider report.Vendor
}

func NewResolver() *Resolver {
	return &Resolver{
		token2: token2resolver.NewLocal(),
		yubico: yubicoresolver.NewLocal(),
		open:   authenticator.Open,
	}
}

// Provider returns the provider proved by transport topology alone. Smart
// cards require protocol probing and therefore have no provider at this stage.
func (r *Resolver) Provider(descriptor discovery.Descriptor) report.Vendor {
	switch {
	case descriptor.VendorID == yubicoVendorID:
		return report.VendorYubico
	case descriptor.VendorID == token2VendorID:
		return report.VendorToken2
	default:
		return report.VendorUnknown
	}
}

// CanResolve reports whether at least one built-in identity provider applies
// to descriptor. Every FIDO smart card is probed because PC/SC does not expose
// the card vendor through USB topology.
func (r *Resolver) CanResolve(descriptor discovery.Descriptor) bool {
	return descriptor.Transport == transport.ModeSmartCard ||
		r.Provider(descriptor) != report.VendorUnknown
}

// Resolve resolves one descriptor.
func (r *Resolver) Resolve(
	ctx context.Context,
	descriptor discovery.Descriptor,
) (Resolution, error) {
	if descriptor.Transport == transport.ModeSmartCard {
		return r.resolveSmartCard(ctx, descriptor)
	}

	provider := r.Provider(descriptor)
	switch provider {
	case report.VendorYubico:
		resolved, err := r.resolveYubico(ctx, descriptor)
		if err != nil {
			return Resolution{}, err
		}

		return Resolution{Identity: resolved, Provider: provider}, nil
	case report.VendorToken2:
		resolved, err := r.resolveToken2(ctx, descriptor)
		if errors.Is(err, token2resolver.ErrNotApplicable) {
			return Resolution{Provider: report.VendorUnknown}, nil
		}
		if errors.Is(err, token2resolver.ErrIdentityUnavailable) ||
			errors.Is(err, token2resolver.ErrAmbiguous) {
			return Resolution{Provider: provider}, nil
		}
		if err != nil {
			return Resolution{}, err
		}

		return Resolution{Identity: resolved, Provider: provider}, nil
	default:
		return Resolution{Provider: report.VendorUnknown}, nil
	}
}

func (r *Resolver) resolveSmartCard(
	ctx context.Context,
	descriptor discovery.Descriptor,
) (Resolution, error) {
	info, err := r.yubico.ResolveSmartCard(ctx, descriptor.Path)
	if err == nil {
		return Resolution{
			Identity: yubicoIdentity("", info),
			Provider: report.VendorYubico,
		}, nil
	}
	if !errors.Is(err, yubicoresolver.ErrNotApplicable) {
		return Resolution{}, err
	}

	resolved, err := r.resolveToken2(ctx, descriptor)
	if errors.Is(err, token2resolver.ErrNotApplicable) {
		return Resolution{Provider: report.VendorUnknown}, nil
	}
	if errors.Is(err, token2resolver.ErrIdentityUnavailable) ||
		errors.Is(err, token2resolver.ErrAmbiguous) {
		return Resolution{Provider: report.VendorToken2}, nil
	}
	if err != nil {
		return Resolution{}, err
	}

	return Resolution{
		Identity: resolved,
		Provider: report.VendorToken2,
	}, nil
}

func (r *Resolver) resolveYubico(
	ctx context.Context,
	descriptor discovery.Descriptor,
) (*report.DeviceIdentity, error) {
	opened, err := r.open(ctx, descriptor.Transport, descriptor.Path)
	if err != nil {
		return nil, err
	}
	defer opened.Lifecycle.Close()

	info, err := yubicoctaphid.GetDeviceInfo(ctx, opened.Vendor)
	if err != nil {
		return nil, err
	}

	return yubicoIdentity(descriptor.Product, info), nil
}

func yubicoIdentity(fallbackModel string, info yubico.DeviceInfo) *report.DeviceIdentity {
	identity := &report.DeviceIdentity{
		Vendor:   report.VendorYubico,
		Model:    info.ModelName(fallbackModel),
		Firmware: info.FirmwareVersion.String(),
		Interfaces: []report.InterfaceReport{{
			Interface: report.InterfaceUSB,
			Supported: yubicoCapabilities(info.SupportedUSBCapabilities),
			Enabled:   yubicoCapabilities(info.EnabledUSBCapabilities),
		}},
		Details: &report.VendorDetails{
			Yubico: yubicoDetails(info),
		},
	}
	if info.Serial != nil {
		identity.Serial = strconv.FormatUint(uint64(*info.Serial), 10)
	}
	if info.HasNFC() {
		var supported, enabled yubico.Capability
		if info.SupportedNFCCapabilities != nil {
			supported = *info.SupportedNFCCapabilities
		}
		if info.EnabledNFCCapabilities != nil {
			enabled = *info.EnabledNFCCapabilities
		}
		identity.Interfaces = append(identity.Interfaces, report.InterfaceReport{
			Interface: report.InterfaceNFC,
			Supported: yubicoCapabilities(supported),
			Enabled:   yubicoCapabilities(enabled),
		})
	}

	return identity
}

func yubicoDetails(info yubico.DeviceInfo) *report.YubicoDetails {
	details := &report.YubicoDetails{
		FormFactor:               yubicoFormFactor(info.FormFactor),
		IsFIPS:                   info.IsFIPS,
		IsSecurityKey:            info.IsSecurityKey,
		AutoEjectTimeout:         info.AutoEjectTimeout,
		ChallengeResponseTimeout: info.ChallengeResponseTimeout,
		Locked:                   info.Locked,
		FIPSCapable:              yubicoCapabilities(info.FIPSCapable),
		FIPSApproved:             yubicoCapabilities(info.FIPSApproved),
		PINComplexity:            info.PinComplexity,
		NFCRestricted:            info.NFCRestricted,
		ResetBlocked:             yubicoCapabilities(info.ResetBlocked),
	}
	if info.PartNumber != nil {
		details.PartNumber = *info.PartNumber
	}
	if effective := info.EffectiveFirmwareVersion().String(); effective != info.FirmwareVersion.String() {
		details.EffectiveFirmware = effective
	}
	if qualifier := info.VersionQualifier; qualifier != nil {
		details.VersionQualifier = &report.YubicoVersionQualifier{
			Version:     qualifier.Version.String(),
			ReleaseType: yubicoReleaseType(qualifier.ReleaseType),
			Iteration:   qualifier.Iteration,
		}
	}
	if info.FPSVersion != nil {
		details.FPSVersion = info.FPSVersion.String()
	}
	if info.STMVersion != nil {
		details.STMVersion = info.STMVersion.String()
	}

	return details
}

func yubicoFormFactor(value yubico.FormFactor) report.YubicoFormFactor {
	switch value {
	case yubico.FormFactorUSBAKeychain:
		return report.YubicoFormFactorUSBAKeychain
	case yubico.FormFactorUSBANano:
		return report.YubicoFormFactorUSBANano
	case yubico.FormFactorUSBCKeychain:
		return report.YubicoFormFactorUSBCKeychain
	case yubico.FormFactorUSBCNano:
		return report.YubicoFormFactorUSBCNano
	case yubico.FormFactorUSBCLightning:
		return report.YubicoFormFactorUSBCLightning
	case yubico.FormFactorUSBABiometricKeychain:
		return report.YubicoFormFactorUSBABiometricKeychain
	case yubico.FormFactorUSBCBiometricKeychain:
		return report.YubicoFormFactorUSBCBiometricKeychain
	default:
		return report.YubicoFormFactorUnknown
	}
}

func yubicoReleaseType(value yubico.ReleaseType) report.YubicoReleaseType {
	switch value {
	case yubico.ReleaseTypeAlpha:
		return report.YubicoReleaseTypeAlpha
	case yubico.ReleaseTypeBeta:
		return report.YubicoReleaseTypeBeta
	default:
		return report.YubicoReleaseTypeFinal
	}
}

func (r *Resolver) resolveToken2(
	ctx context.Context,
	descriptor discovery.Descriptor,
) (*report.DeviceIdentity, error) {
	var (
		result token2resolver.Result
		err    error
	)

	switch descriptor.Transport {
	case transport.ModeSmartCard:
		result, err = r.token2.ResolveSmartCard(ctx, descriptor.Path)
	default:
		target := token2resolver.HIDTarget{
			ReportedSerial: descriptor.Serial,
			ProductID:      descriptor.ProductID,
			InstanceID:     descriptor.InstanceID,
			ParentDeviceID: descriptor.ParentDeviceID,
		}

		opened, openErr := r.open(ctx, descriptor.Transport, descriptor.Path)
		if openErr == nil {
			defer opened.Lifecycle.Close()
			if atr, atrErr := token2ctaphid.ReadATR(ctx, opened.Vendor); atrErr == nil {
				target.ATR = &atr
			}
		}

		result, err = r.token2.ResolveHID(ctx, target)
	}
	if err != nil {
		return nil, err
	}

	identity := &report.DeviceIdentity{
		Vendor: report.VendorToken2,
		Serial: result.Identity.SerialNumber,
	}
	if result.ModelKnown {
		identity.Model = token2ModelName(result.Identity.Model)
		identity.Firmware = strings.TrimSpace(result.Identity.Model.Release)
	}

	return identity, nil
}

func yubicoCapabilities(value yubico.Capability) []report.Capability {
	known := []struct {
		vendor yubico.Capability
		report report.Capability
	}{
		{yubico.CapabilityOTP, report.CapabilityOTP},
		{yubico.CapabilityU2F, report.CapabilityU2F},
		{yubico.CapabilityCCID, report.CapabilityCCID},
		{yubico.CapabilityOpenPGP, report.CapabilityOpenPGP},
		{yubico.CapabilityPIV, report.CapabilityPIV},
		{yubico.CapabilityOATH, report.CapabilityOATH},
		{yubico.CapabilityHSMAuth, report.CapabilityHSMAuth},
		{yubico.CapabilityCTAP2, report.CapabilityCTAP2},
	}

	var result []report.Capability
	for _, capability := range known {
		if value&capability.vendor != 0 {
			result = append(result, capability.report)
		}
	}
	return result
}
