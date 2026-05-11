package config

import (
	"fmt"

	"github.com/go-ctap/kit/model/safety"
)

const (
	warningPINSetMutation    = "pin.set.mutation"
	warningPINChangeMutation = "pin.change.mutation"
	warningPINDryRunLocal    = "pin.dry_run.local_only"
)

func BuildSetPINPreview(status StatusReport, mode safety.PreviewMode) (PINMutationPreview, error) {
	return buildPINPreview(status, PINMutationSet, mode)
}

func BuildChangePINPreview(status StatusReport, mode safety.PreviewMode) (PINMutationPreview, error) {
	return buildPINPreview(status, PINMutationChange, mode)
}

func buildPINPreview(status StatusReport, operation PINMutationOperation, mode safety.PreviewMode) (PINMutationPreview, error) {
	if !status.PIN.Supported {
		return PINMutationPreview{}, fmt.Errorf("%w: device does not report clientPin support", ErrPINUnsupported)
	}

	configured := status.PIN.Configured != nil && *status.PIN.Configured

	switch operation {
	case PINMutationSet:
		if configured {
			return PINMutationPreview{}, fmt.Errorf("%w: use config pin change", ErrPINAlreadyConfigured)
		}
	case PINMutationChange:
		if !configured {
			return PINMutationPreview{}, fmt.Errorf("%w: use config pin set", ErrPINNotConfigured)
		}
	default:
		return PINMutationPreview{}, fmt.Errorf("ctapkit: unsupported PIN operation %q", operation)
	}

	warnings := []safety.Warning{pinMutationWarning(operation)}
	if mode == safety.PreviewModeDryRun {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityInfo,
			Code:     warningPINDryRunLocal,
			Message:  "Dry-run validates local PIN entry and renders this preview only; no PIN mutation is sent to the authenticator.",
		})
	}

	return PINMutationPreview{
		Operation: operation,
		Device:    status.Device,
		PIN:       status.PIN,
		Mode:      mode,
		Warnings:  warnings,
	}, nil
}

func pinMutationWarning(operation PINMutationOperation) safety.Warning {
	switch operation {
	case PINMutationSet:
		return safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningPINSetMutation,
			Message:  "A new PIN will be configured on this authenticator.",
		}
	case PINMutationChange:
		return safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningPINChangeMutation,
			Message:  "The existing PIN on this authenticator will be changed.",
		}
	default:
		return safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     "pin.mutation",
			Message:  "A PIN mutation will be sent to this authenticator.",
		}
	}
}
