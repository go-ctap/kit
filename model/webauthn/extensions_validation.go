package webauthn

import (
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model/safety"
)

func normalizeMakeCredentialExtensions(
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
) *ctapwebauthn.CreateAuthenticationExtensionsClientInputs {
	if input == nil {
		return nil
	}

	result := *input
	result.CreateCredentialPropertiesInputs = clonePointer(input.CreateCredentialPropertiesInputs)
	result.CreateHMACSecretInputs = clonePointer(input.CreateHMACSecretInputs)
	result.CreateMinPinLengthInputs = clonePointer(input.CreateMinPinLengthInputs)
	result.CreatePinComplexityPolicyInputs = clonePointer(input.CreatePinComplexityPolicyInputs)
	if input.CreateCredentialProtectionInputs != nil {
		value := *input.CreateCredentialProtectionInputs
		result.CreateCredentialProtectionInputs = &value
	}
	if input.CreateCredentialBlobInputs != nil {
		value := *input.CreateCredentialBlobInputs
		value.CredBlob = slices.Clone(value.CredBlob)
		result.CreateCredentialBlobInputs = &value
	}
	if input.CreateHMACSecretMCInputs != nil {
		value := *input.CreateHMACSecretMCInputs
		value.HMACGetSecret = cloneHMACSecretInput(value.HMACGetSecret)
		result.CreateHMACSecretMCInputs = &value
	}
	if input.PRFInputs != nil {
		result.PRFInputs = &ctapwebauthn.PRFInputs{PRF: normalizePRFInputs(input.PRF)}
	}

	return &result
}

func normalizeGetAssertionExtensions(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
) *ctapwebauthn.GetAuthenticationExtensionsClientInputs {
	if input == nil {
		return nil
	}

	result := *input
	result.GetCredentialBlobInputs = clonePointer(input.GetCredentialBlobInputs)
	if input.GetHMACSecretInputs != nil {
		value := *input.GetHMACSecretInputs
		value.HMACGetSecret = cloneHMACSecretInput(value.HMACGetSecret)
		result.GetHMACSecretInputs = &value
	}
	if input.PRFInputs != nil {
		result.PRFInputs = &ctapwebauthn.PRFInputs{PRF: normalizePRFInputs(input.PRF)}
	}

	return &result
}

func cloneHMACSecretInput(
	input ctapwebauthn.HMACGetSecretInput,
) ctapwebauthn.HMACGetSecretInput {
	return ctapwebauthn.HMACGetSecretInput{
		Salt1: slices.Clone(input.Salt1),
		Salt2: slices.Clone(input.Salt2),
	}
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
		appendMissing(true, extension.ExtensionIdentifierHMACSecret,
			"webauthn.extension.prf.not_advertised", "prf")
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

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value

	return &cloned
}
