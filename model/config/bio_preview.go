package config

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ctap/kit/model/safety"
)

const (
	warningBioEnrollMutation = "bio.enroll.mutation"
	warningBioRenameMutation = "bio.rename.mutation"
	warningBioRemoveMutation = "bio.remove.destructive"
)

type BioEnrollProgress func(BioEnrollSample) error

type BioEnrollError struct {
	Result BioEnrollResult
	Err    error
}

func (e BioEnrollError) Error() string {
	if e.Err == nil {
		return ErrBioEnrollmentFailed.Error()
	}

	return e.Err.Error()
}

func (e BioEnrollError) Unwrap() error {
	return e.Err
}

func BuildBioEnrollPreview(
	status StatusReport,
	timeoutMilliseconds uint,
	mode safety.PreviewMode,
) (BioEnrollPreview, error) {
	if !status.Bio.Supported {
		return BioEnrollPreview{}, fmt.Errorf("%w: device does not report bioEnroll support", ErrBioUnsupported)
	}

	warnings := []safety.Warning{{
		Severity: safety.SeverityWarning,
		Code:     warningBioEnrollMutation,
		Message:  "A biometric enrollment workflow will be started on this authenticator.",
	}}

	return BioEnrollPreview{
		Device:              status.Device,
		PreviewOnly:         status.Bio.PreviewOnly,
		TimeoutMilliseconds: timeoutMilliseconds,
		Mode:                mode,
		Warnings:            warnings,
	}, nil
}

func BuildBioRenamePreview(
	status StatusReport,
	templateIDHex string,
	friendlyName string,
	mode safety.PreviewMode,
) (BioMutationPreview, error) {
	return buildBioMutationPreview(status, BioMutationRename, templateIDHex, friendlyName, mode)
}

func BuildBioRemovePreview(
	status StatusReport,
	templateIDHex string,
	mode safety.PreviewMode,
) (BioMutationPreview, error) {
	return buildBioMutationPreview(status, BioMutationRemove, templateIDHex, "", mode)
}

func buildBioMutationPreview(
	status StatusReport,
	operation BioMutationOperation,
	templateIDHex string,
	friendlyName string,
	mode safety.PreviewMode,
) (BioMutationPreview, error) {
	if !status.Bio.Supported {
		return BioMutationPreview{}, fmt.Errorf("%w: device does not report bioEnroll support", ErrBioUnsupported)
	}
	if status.Bio.Configured != nil && !*status.Bio.Configured {
		return BioMutationPreview{}, fmt.Errorf("%w: device reports no biometric enrollments", ErrBioNoEnrollments)
	}

	if _, err := decodeTemplateID(templateIDHex); err != nil {
		return BioMutationPreview{}, err
	}

	warning := safety.Warning{
		Severity: safety.SeverityWarning,
		Code:     warningBioRenameMutation,
		Message:  "The friendly name metadata for this biometric enrollment will be changed.",
	}
	if operation == BioMutationRemove {
		warning = safety.Warning{
			Severity: safety.SeverityDestructive,
			Code:     warningBioRemoveMutation,
			Message:  "This biometric enrollment template will be removed from the authenticator.",
		}
	}

	return BioMutationPreview{
		Operation:     operation,
		Device:        status.Device,
		PreviewOnly:   status.Bio.PreviewOnly,
		TemplateIDHex: templateIDHex,
		FriendlyName:  friendlyName,
		Mode:          mode,
		Warnings:      []safety.Warning{warning},
	}, nil
}

func decodeTemplateID(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: template ID is required", ErrBioTemplateID)
	}

	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: template ID must be valid hex", ErrBioTemplateID)
	}

	return decoded, nil
}

func DecodeTemplateID(value string) ([]byte, error) {
	return decodeTemplateID(value)
}
