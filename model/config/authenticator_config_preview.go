package config

import (
	"fmt"

	"github.com/go-ctap/kit/model/safety"
	"github.com/samber/lo"
)

const (
	warningAlwaysUVChange                = "config.always_uv.change"
	warningMinPINLengthPolicy            = "config.min_pin_length.policy"
	warningMinPINLengthIrreversible      = "config.min_pin_length.irreversible"
	warningMinPINLengthEnterpriseOverlap = "config.min_pin_length.enterprise_overlap"
)

func BuildAlwaysUVPreview(status StatusReport, target AlwaysUVTarget, mode safety.PreviewMode) (AuthenticatorConfigPreview, error) {
	requested := target == AlwaysUVTargetEnable

	if !status.AuthenticatorConfig.Supported {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: device does not report authnrCfg support", ErrAuthenticatorConfigUnsupported)
	}

	alwaysUV := status.AuthenticatorConfig.AlwaysUV
	if !alwaysUV.Supported {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: device does not report alwaysUv support", ErrAuthenticatorConfigUnsupported)
	}

	if alwaysUV.Configured == nil || alwaysUV.State == StateUnknown {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: current state is unknown", ErrAlwaysUVStateUnknown)
	}

	if *alwaysUV.Configured == requested {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: current state already matches %s", ErrAlwaysUVAlreadyTarget, target)
	}

	return AuthenticatorConfigPreview{
		Operation:         AuthenticatorConfigAlwaysUV,
		Device:            status.Device,
		Authenticator:     status.AuthenticatorConfig,
		Target:            target,
		CurrentAlwaysUV:   alwaysUV.Configured,
		RequestedAlwaysUV: requested,
		Mode:              mode,
		Warnings: []safety.Warning{{
			Severity: safety.SeverityWarning,
			Code:     warningAlwaysUVChange,
			Message:  "The authenticator alwaysUv setting will be changed to the requested target state.",
		}},
	}, nil
}

func BuildMinPINLengthPreview(status StatusReport, req MinPINLengthRequest, mode safety.PreviewMode) (AuthenticatorConfigPreview, error) {
	if !status.AuthenticatorConfig.Supported {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: device does not report authnrCfg support", ErrAuthenticatorConfigUnsupported)
	}

	if !status.AuthenticatorConfig.SetMinPINLength.Supported {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: device does not report setMinPINLength support", ErrMinPINLengthUnsupported)
	}

	if status.PIN.MinPINLength != nil && req.Length < *status.PIN.MinPINLength {
		return AuthenticatorConfigPreview{}, fmt.Errorf("%w: requested %d current %d", ErrMinPINLengthLowering, req.Length, *status.PIN.MinPINLength)
	}

	warnings := []safety.Warning{
		{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthPolicy,
			Message:  "CTAP setMinPINLength changes authenticator PIN policy; behavior is enforced by the authenticator and relying-party visibility is limited by spec rules.",
		},
		{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthIrreversible,
			Message:  "Some authenticators may reject later attempts to lower the minimum PIN length or may require PIN change after policy updates.",
		},
	}
	if len(req.RPIDs) > 0 {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthEnterpriseOverlap,
			Message:  "RP ID scoping overlaps with relying-party policy visibility; enterprise attestation and enterprise policy commands remain deferred.",
		})
	}

	return AuthenticatorConfigPreview{
		Operation:             AuthenticatorConfigMinPINLength,
		Device:                status.Device,
		Authenticator:         status.AuthenticatorConfig,
		CurrentMinPINLength:   status.PIN.MinPINLength,
		RequestedMinPINLength: new(req.Length),
		MaxPINLength:          status.PIN.MaxPINLength,
		RPIDs:                 lo.Clone(req.RPIDs),
		ForceChangePin:        req.ForceChangePin,
		PinComplexityPolicy:   req.PinComplexityPolicy,
		Mode:                  mode,
		Warnings:              warnings,
	}, nil
}
