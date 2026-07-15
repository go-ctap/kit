package webauthn

import (
	"bytes"
	"encoding/base64"
	"slices"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func normalizeMakeCredentialExtensions(
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
) (*ctapwebauthn.CreateAuthenticationExtensionsClientInputs, error) {
	if input == nil {
		return nil, nil
	}
	if input.CreateHMACSecretMCInputs != nil && hasPRFEvaluation(input.PRFInputs) {
		return nil, extensionFailure(failure.CodeWebAuthnExtensionConflict)
	}
	if input.CreateHMACSecretInputs != nil && !input.HMACCreateSecret && input.PRFInputs != nil {
		return nil, extensionFailure(failure.CodeWebAuthnExtensionConflict)
	}

	result := *input
	result.CreateCredentialPropertiesInputs = clonePointer(input.CreateCredentialPropertiesInputs)
	result.CreateHMACSecretInputs = clonePointer(input.CreateHMACSecretInputs)
	result.CreateMinPinLengthInputs = clonePointer(input.CreateMinPinLengthInputs)
	result.CreatePinComplexityPolicyInputs = clonePointer(input.CreatePinComplexityPolicyInputs)
	if input.CreateCredentialProtectionInputs != nil {
		value := *input.CreateCredentialProtectionInputs
		if value.CredentialProtectionPolicy != extension.CredentialProtectionPolicyUserVerificationOptional &&
			value.CredentialProtectionPolicy != extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList &&
			value.CredentialProtectionPolicy != extension.CredentialProtectionPolicyUserVerificationRequired {
			return nil, extensionFailure(failure.CodeWebAuthnExtensionInputInvalid)
		}
		result.CreateCredentialProtectionInputs = &value
	}
	if input.CreateCredentialBlobInputs != nil {
		value := *input.CreateCredentialBlobInputs
		value.CredBlob = slices.Clone(value.CredBlob)
		result.CreateCredentialBlobInputs = &value
	}
	if input.CreateHMACSecretMCInputs != nil {
		value := *input.CreateHMACSecretMCInputs
		hmacInput, err := normalizeHMACSecretInput(value.HMACGetSecret)
		if err != nil {
			return nil, err
		}
		value.HMACGetSecret = hmacInput
		result.CreateHMACSecretMCInputs = &value
	}
	if input.PRFInputs != nil {
		if input.PRF.EvalByCredential != nil {
			return nil, extensionFailure(failure.CodeWebAuthnPRFEvaluationInvalid)
		}
		result.PRFInputs = &ctapwebauthn.PRFInputs{PRF: normalizePRFInputs(input.PRF)}
	}

	return &result, nil
}

func normalizeGetAssertionExtensions(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	allowList []credential.PublicKeyCredentialDescriptor,
) (*ctapwebauthn.GetAuthenticationExtensionsClientInputs, error) {
	if input == nil {
		return nil, nil
	}
	if input.GetHMACSecretInputs != nil && hasPRFEvaluation(input.PRFInputs) {
		return nil, extensionFailure(failure.CodeWebAuthnExtensionConflict)
	}

	result := *input
	result.GetCredentialBlobInputs = clonePointer(input.GetCredentialBlobInputs)
	if input.GetHMACSecretInputs != nil {
		value := *input.GetHMACSecretInputs
		hmacInput, err := normalizeHMACSecretInput(value.HMACGetSecret)
		if err != nil {
			return nil, err
		}
		value.HMACGetSecret = hmacInput
		result.GetHMACSecretInputs = &value
	}
	if input.PRFInputs != nil {
		result.PRFInputs = &ctapwebauthn.PRFInputs{PRF: normalizePRFInputs(input.PRF)}
		if len(input.PRF.EvalByCredential) > 0 {
			if len(allowList) != 1 {
				return nil, extensionFailure(failure.CodeWebAuthnPRFEvaluationInvalid)
			}
			result.PRF.EvalByCredential = make(map[string]ctapwebauthn.AuthenticationExtensionsPRFValues,
				len(input.PRF.EvalByCredential))
			for key, values := range input.PRF.EvalByCredential {
				credentialID, err := base64.RawURLEncoding.DecodeString(key)
				if err != nil || len(credentialID) == 0 ||
					base64.RawURLEncoding.EncodeToString(credentialID) != key ||
					!descriptorListContains(allowList, credentialID) {
					return nil, extensionFailure(failure.CodeWebAuthnPRFEvaluationInvalid)
				}
				result.PRF.EvalByCredential[key] = normalizePRFValues(values)
			}
		}
	}

	return &result, nil
}

func normalizeHMACSecretInput(
	input ctapwebauthn.HMACGetSecretInput,
) (ctapwebauthn.HMACGetSecretInput, error) {
	if len(input.Salt1) != 32 || len(input.Salt2) != 0 && len(input.Salt2) != 32 {
		return ctapwebauthn.HMACGetSecretInput{}, extensionFailure(failure.CodeWebAuthnSecretSaltLengthInvalid)
	}

	return ctapwebauthn.HMACGetSecretInput{
		Salt1: slices.Clone(input.Salt1),
		Salt2: slices.Clone(input.Salt2),
	}, nil
}

func normalizePRFInputs(
	input ctapwebauthn.AuthenticationExtensionsPRFInputs,
) ctapwebauthn.AuthenticationExtensionsPRFInputs {
	result := ctapwebauthn.AuthenticationExtensionsPRFInputs{
		Eval: normalizePRFValues(input.Eval),
	}
	if input.EvalByCredential != nil {
		result.EvalByCredential = make(map[string]ctapwebauthn.AuthenticationExtensionsPRFValues,
			len(input.EvalByCredential))
		for key, values := range input.EvalByCredential {
			result.EvalByCredential[key] = normalizePRFValues(values)
		}
	}

	return result
}

func normalizePRFValues(
	input ctapwebauthn.AuthenticationExtensionsPRFValues,
) ctapwebauthn.AuthenticationExtensionsPRFValues {
	return ctapwebauthn.AuthenticationExtensionsPRFValues{
		First:  slices.Clone(input.First),
		Second: slices.Clone(input.Second),
	}
}

func hasPRFEvaluation(input *ctapwebauthn.PRFInputs) bool {
	return input != nil && (!input.PRF.Eval.IsZero() || len(input.PRF.EvalByCredential) > 0)
}

func validateMakeCredentialCapabilities(
	info protocol.AuthenticatorGetInfoResponse,
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
) error {
	if input == nil || input.CreateCredentialBlobInputs == nil || info.MaxCredBlobLength == nil {
		return nil
	}
	if uint(len(input.CredBlob)) > *info.MaxCredBlobLength {
		return extensionFailure(failure.CodeWebAuthnExtensionInputInvalid)
	}

	return nil
}

func makeCredentialExtensionWarnings(
	info protocol.AuthenticatorGetInfoResponse,
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
) []safety.Warning {
	if input == nil {
		return nil
	}

	warnings := make([]safety.Warning, 0, 7)
	appendMissing := func(included bool, identifier extension.ExtensionIdentifier, code, label string) {
		if included && !slices.Contains(info.Extensions, identifier) {
			warnings = append(warnings, unsupportedExtensionWarning(code, label))
		}
	}
	appendMissing(input.CreateCredentialProtectionInputs != nil, extension.ExtensionIdentifierCredentialProtection,
		"webauthn.extension.cred_protect.not_advertised", "credProtect")
	appendMissing(input.CreateCredentialBlobInputs != nil, extension.ExtensionIdentifierCredentialBlob,
		"webauthn.extension.cred_blob.not_advertised", "credBlob")
	appendMissing(input.CreateHMACSecretInputs != nil, extension.ExtensionIdentifierHMACSecret,
		"webauthn.extension.hmac_secret.not_advertised", "hmac-secret")
	appendMissing(input.CreateHMACSecretMCInputs != nil, extension.ExtensionIdentifierHMACSecretMC,
		"webauthn.extension.hmac_secret_mc.not_advertised", "hmac-secret-mc")
	appendMissing(input.CreateMinPinLengthInputs != nil, extension.ExtensionIdentifierMinPinLength,
		"webauthn.extension.min_pin_length.not_advertised", "minPinLength")
	appendMissing(input.CreatePinComplexityPolicyInputs != nil, extension.ExtensionIdentifierPinComplexityPolicy,
		"webauthn.extension.pin_complexity_policy.not_advertised", "pinComplexityPolicy")
	if input.PRFInputs != nil {
		identifier := extension.ExtensionIdentifierHMACSecret
		if !input.PRF.Eval.IsZero() {
			identifier = extension.ExtensionIdentifierHMACSecretMC
		}
		appendMissing(true, identifier, "webauthn.extension.prf.not_advertised", "prf")
	}

	return warnings
}

func getAssertionExtensionWarnings(
	info protocol.AuthenticatorGetInfoResponse,
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
) []safety.Warning {
	if input == nil {
		return nil
	}

	warnings := make([]safety.Warning, 0, 3)
	if input.GetCredentialBlobInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierCredentialBlob) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.cred_blob.not_advertised", "credBlob"))
	}
	if input.GetHMACSecretInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.hmac_secret.not_advertised", "hmac-secret"))
	}
	if hasPRFEvaluation(input.PRFInputs) && !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.prf.not_advertised", "prf"))
	}

	return warnings
}

func unsupportedExtensionWarning(code, label string) safety.Warning {
	return safety.Warning{
		Severity: safety.SeverityWarning,
		Code:     code,
		Message:  label + " is not advertised by this authenticator; execution is still allowed.",
	}
}

func descriptorListContains(
	descriptors []credential.PublicKeyCredentialDescriptor,
	credentialID []byte,
) bool {
	return slices.ContainsFunc(descriptors, func(descriptor credential.PublicKeyCredentialDescriptor) bool {
		return bytes.Equal(descriptor.ID, credentialID)
	})
}

func extensionFailure(code failure.Code) error {
	return failure.New(code, failure.WithPhase(failure.PhaseValidation))
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value

	return &cloned
}
