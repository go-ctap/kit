package config

import (
	"strconv"

	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

const (
	warningAlwaysUVChange                = "config.always_uv.change"
	warningMinPINLengthPolicy            = "config.min_pin_length.policy"
	warningMinPINLengthIrreversible      = "config.min_pin_length.irreversible"
	warningMinPINLengthEnterpriseOverlap = "config.min_pin_length.enterprise_overlap"
	warningLongTouchForReset             = "config.long_touch_for_reset.enable"
)

func BuildAlwaysUVPreview(status StatusReport, target AlwaysUVTarget, mode safety.PreviewMode) (AuthenticatorConfigPreview, error) {
	requested := target == AlwaysUVTargetEnable

	if !status.AuthenticatorConfig.Supported {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeAuthenticatorConfigUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	alwaysUV := status.AuthenticatorConfig.AlwaysUV
	if !alwaysUV.Supported {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeAuthenticatorConfigUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if alwaysUV.Configured == nil || alwaysUV.State == StateUnknown {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeAlwaysUVStateUnknown, failure.WithPhase(failure.PhaseValidation))
	}

	if *alwaysUV.Configured == requested {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeAlwaysUVAlreadyTarget, failure.WithPhase(failure.PhaseValidation))
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

func BuildEnableLongTouchForResetPreview(status StatusReport, mode safety.PreviewMode) (AuthenticatorConfigPreview, error) {
	capability := status.AuthenticatorConfig.LongTouchForReset
	if !status.AuthenticatorConfig.Supported || !capability.Supported || capability.Configured == nil {
		return AuthenticatorConfigPreview{}, failure.New(
			failure.CodeAuthenticatorConfigUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	if *capability.Configured {
		return AuthenticatorConfigPreview{}, failure.New(
			failure.CodeAuthenticatorOperationNotAllowed,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return AuthenticatorConfigPreview{
		Operation:          AuthenticatorConfigLongTouch,
		Device:             status.Device,
		Authenticator:      status.AuthenticatorConfig,
		CurrentLongTouch:   capability.Configured,
		RequestedLongTouch: true,
		Mode:               mode,
		Warnings: []safety.Warning{{
			Severity: safety.SeverityWarning,
			Code:     warningLongTouchForReset,
			Message:  "Factory reset will require the authenticator's long-touch gesture after this setting is enabled.",
		}},
	}, nil
}

func BuildMinPINLengthPreview(status StatusReport, req MinPINLengthRequest, mode safety.PreviewMode) (AuthenticatorConfigPreview, error) {
	if !status.AuthenticatorConfig.Supported {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeAuthenticatorConfigUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if !status.AuthenticatorConfig.SetMinPINLength.Supported {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeMinPINLengthUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if req.NewMinPINLength == nil && len(req.MinPINLengthRPIDs) == 0 && !req.ForceChangePIN && !req.PINComplexityPolicy {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeCTAPParameterMissing, failure.WithPhase(failure.PhaseValidation))
	}

	if req.NewMinPINLength != nil && *req.NewMinPINLength < status.PIN.MinPINLength {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeMinPINLengthDecreaseNotAllowed,
			failure.WithParams(map[string]string{
				"requested": strconv.FormatUint(uint64(*req.NewMinPINLength), 10),
				"current":   strconv.FormatUint(uint64(status.PIN.MinPINLength), 10),
			}),
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	if req.NewMinPINLength != nil && *req.NewMinPINLength > status.PIN.MaxPINLength {
		return AuthenticatorConfigPreview{}, failure.New(failure.CodeCTAPParameterInvalid, failure.WithPhase(failure.PhaseValidation))
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

	if len(req.MinPINLengthRPIDs) > 0 {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthEnterpriseOverlap,
			Message:  "RP ID scoping overlaps with relying-party policy visibility; enterprise attestation and enterprise policy commands remain deferred.",
		})
	}

	return AuthenticatorConfigPreview{
		Operation:           AuthenticatorConfigMinPINLength,
		Device:              status.Device,
		Authenticator:       status.AuthenticatorConfig,
		CurrentMinPINLength: status.PIN.MinPINLength,
		NewMinPINLength:     req.NewMinPINLength,
		MaxPINLength:        status.PIN.MaxPINLength,
		MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
		ForceChangePIN:      req.ForceChangePIN,
		PINComplexityPolicy: req.PINComplexityPolicy,
		Mode:                mode,
		Warnings:            warnings,
	}, nil
}
