package webauthn

import (
	"strings"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
	"github.com/samber/lo"
)

func BuildMakeCredentialPreview(
	device report.DeviceReport,
	info protocol.AuthenticatorGetInfoResponse,
	input appwebauthn.MakeCredentialInput,
) (appwebauthn.MakeCredentialPreview, error) {
	normalized, err := NormalizeMakeCredentialInput(input)
	if err != nil {
		return appwebauthn.MakeCredentialPreview{}, err
	}

	warnings := []safety.Warning{{
		Severity: safety.SeverityWarning,
		Code:     "webauthn.make_credential.mutation",
		Message:  "On success, authenticatorMakeCredential creates a new credential key pair.",
	}}
	if normalized.Options.ResidentKey != nil && *normalized.Options.ResidentKey {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityDestructive,
			Code:     "webauthn.make_credential.discoverable_overwrite",
			Message:  "With rk=true, an existing discoverable credential for the same RP ID and user ID is overwritten; its old credential ID stops resolving, and its large blob may be erased or orphaned.",
		})
	}
	warnings = append(warnings, makeCredentialExtensionWarnings(info, normalized.Extensions)...)

	return appwebauthn.MakeCredentialPreview{
		Device:   device,
		Input:    normalized,
		Warnings: warnings,
	}, nil
}

func BuildGetAssertionPreview(
	device report.DeviceReport,
	info protocol.AuthenticatorGetInfoResponse,
	input appwebauthn.GetAssertionInput,
) (appwebauthn.GetAssertionPreview, error) {
	normalized, err := NormalizeGetAssertionInput(input)
	if err != nil {
		return appwebauthn.GetAssertionPreview{}, err
	}

	return appwebauthn.GetAssertionPreview{
		Device:   device,
		Input:    normalized,
		Warnings: getAssertionExtensionWarnings(info, normalized.Extensions),
	}, nil
}

func NormalizeMakeCredentialInput(
	input appwebauthn.MakeCredentialInput,
) (appwebauthn.MakeCredentialInput, error) {
	input.RP.ID = strings.TrimSpace(input.RP.ID)
	input.RP.Name = strings.TrimSpace(input.RP.Name)
	if input.RP.ID == "" {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeRelyingPartyIDRequired)
	}

	input.User.Name = strings.TrimSpace(input.User.Name)
	input.User.DisplayName = strings.TrimSpace(input.User.DisplayName)
	if len(input.User.ID) == 0 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeUserIDRequired)
	}

	if len(input.User.ID) > 64 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPLengthInvalid)
	}

	if len(input.ClientDataJSON) == 0 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeClientDataJSONRequired)
	}

	if len(input.PubKeyCredParams) == 0 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(
			failure.CodePublicKeyCredentialParametersRequired,
		)
	}

	seenParameters := make(map[credential.PublicKeyCredentialParameters]struct{}, len(input.PubKeyCredParams))
	pubKeyCredParams, err := lo.MapErr(
		input.PubKeyCredParams,
		func(param credential.PublicKeyCredentialParameters, _ int) (credential.PublicKeyCredentialParameters, error) {
			param = normalizeCredentialParameter(param)
			if param.Algorithm == 0 {
				return credential.PublicKeyCredentialParameters{}, validationFailure(
					failure.CodePublicKeyCredentialAlgorithmRequired,
				)
			}

			if _, duplicate := seenParameters[param]; duplicate {
				return credential.PublicKeyCredentialParameters{}, validationFailure(failure.CodeCTAPParameterInvalid)
			}
			seenParameters[param] = struct{}{}

			return param, nil
		},
	)
	if err != nil {
		return appwebauthn.MakeCredentialInput{}, err
	}

	input.PubKeyCredParams = pubKeyCredParams
	if input.Options.UserPresence != nil && !*input.Options.UserPresence {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPOptionInvalid)
	}

	if input.EnterpriseAttestation > 2 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPOptionInvalid)
	}

	for index, format := range input.AttestationFormatsPreference {
		normalized := attestation.AttestationStatementFormatIdentifier(strings.TrimSpace(string(format)))
		if normalized == "" {
			return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPParameterInvalid)
		}
		input.AttestationFormatsPreference[index] = normalized
	}

	excludeList, err := normalizeDescriptors(input.ExcludeList)
	if err != nil {
		return appwebauthn.MakeCredentialInput{}, err
	}
	input.ExcludeList = excludeList

	return input, nil
}

func NormalizeGetAssertionInput(
	input appwebauthn.GetAssertionInput,
) (appwebauthn.GetAssertionInput, error) {
	input.RPID = strings.TrimSpace(input.RPID)
	if input.RPID == "" {
		return appwebauthn.GetAssertionInput{}, validationFailure(failure.CodeRelyingPartyIDRequired)
	}

	if len(input.ClientDataJSON) == 0 {
		return appwebauthn.GetAssertionInput{}, validationFailure(failure.CodeClientDataJSONRequired)
	}

	allowList, err := normalizeDescriptors(input.AllowList)
	if err != nil {
		return appwebauthn.GetAssertionInput{}, err
	}
	input.AllowList = allowList

	return input, nil
}

func normalizeDescriptors(
	in []credential.PublicKeyCredentialDescriptor,
) ([]credential.PublicKeyCredentialDescriptor, error) {
	return lo.MapErr(
		in,
		func(descriptor credential.PublicKeyCredentialDescriptor, _ int) (credential.PublicKeyCredentialDescriptor, error) {
			descriptor.Type = credentialTypeOrDefault(descriptor.Type)
			if len(descriptor.ID) == 0 {
				return credential.PublicKeyCredentialDescriptor{}, validationFailure(failure.CodeCredentialIDRequired)
			}

			return descriptor, nil
		},
	)
}

func normalizeCredentialParameter(
	param credential.PublicKeyCredentialParameters,
) credential.PublicKeyCredentialParameters {
	param.Type = credentialTypeOrDefault(param.Type)

	return param
}

func credentialTypeOrDefault(value credential.PublicKeyCredentialType) credential.PublicKeyCredentialType {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return appwebauthn.PublicKeyCredentialTypePublicKey
	}

	return credential.PublicKeyCredentialType(trimmed)
}

func validationFailure(code failure.Code) error {
	return failure.New(code, failure.WithPhase(failure.PhaseValidation))
}
