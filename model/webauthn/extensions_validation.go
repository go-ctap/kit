package webauthn

import (
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model/safety"
)

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
	appendMissing(input.LargeBlobInputs != nil, extension.ExtensionIdentifierLargeBlobKey,
		"webauthn.extension.large_blob.not_advertised", "largeBlob")
	appendMissing(input.PaymentInputs != nil && input.Payment.IsPayment, extension.ExtensionIdentifierThirdPartyPayment,
		"webauthn.extension.third_party_payment.not_advertised", "thirdPartyPayment")
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

	if input.LargeBlobInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.large_blob.not_advertised", "largeBlob"))
	}

	if input.PaymentInputs != nil && input.Payment.IsPayment &&
		!slices.Contains(info.Extensions, extension.ExtensionIdentifierThirdPartyPayment) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.third_party_payment.not_advertised", "thirdPartyPayment"))
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
