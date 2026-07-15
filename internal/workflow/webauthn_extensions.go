package workflow

import (
	"encoding/hex"
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
)

func ctapMakeCredentialExtensions(
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	info protocol.AuthenticatorGetInfoResponse,
) *ctapwebauthn.CreateAuthenticationExtensionsClientInputs {
	if input == nil {
		return nil
	}

	result := *input
	if input.PRFInputs != nil {
		result.PRFInputs = nil
		switch {
		case !input.PRF.Eval.IsZero() && slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC):
			result.PRFInputs = input.PRFInputs
		case slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret):
			result.CreateHMACSecretInputs = &ctapwebauthn.CreateHMACSecretInputs{HMACCreateSecret: true}
		}
	}

	return &result
}

func ctapGetAssertionExtensions(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	info protocol.AuthenticatorGetInfoResponse,
) *ctapwebauthn.GetAuthenticationExtensionsClientInputs {
	if input == nil {
		return nil
	}

	result := *input
	result.PRFInputs = nil
	if prfHasEvaluation(input.PRFInputs) &&
		slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		result.PRFInputs = input.PRFInputs
	}

	return &result
}

func prfHasEvaluation(input *ctapwebauthn.PRFInputs) bool {
	return input != nil && (!input.PRF.Eval.IsZero() || len(input.PRF.EvalByCredential) > 0)
}

func makeCredentialExtensionResults(
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorMakeCredentialResponse,
) *appwebauthn.MakeCredentialExtensionResults {
	output := response.ExtensionOutputs
	var authenticatorOutput *protocol.CreateExtensionOutputs
	if response.AuthData != nil {
		authenticatorOutput = response.AuthData.Extensions
	}

	result := new(appwebauthn.MakeCredentialExtensionResults)
	client := new(appwebauthn.MakeCredentialClientExtensionResults)
	authenticator := new(appwebauthn.MakeCredentialAuthenticatorExtensionOutputs)
	hasClientResult := false
	hasAuthenticatorOutput := false
	if output != nil && output.CreateCredentialPropertiesOutputs != nil {
		hasClientResult = true
		client.CredentialProperties = &output.CredentialProperties
	}
	if authenticatorOutput != nil && authenticatorOutput.CreateCredProtectOutput != nil {
		hasAuthenticatorOutput = true
		policy := extension.CredentialProtectionPolicy("")
		switch authenticatorOutput.CreateCredProtectOutput.CredProtect {
		case 0x01:
			policy = extension.CredentialProtectionPolicyUserVerificationOptional
		case 0x02:
			policy = extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList
		case 0x03:
			policy = extension.CredentialProtectionPolicyUserVerificationRequired
		}
		authenticator.CredentialProtection = &appwebauthn.CredentialProtectionOutput{Policy: policy}
	}
	if output != nil && output.CreateCredentialBlobOutputs != nil {
		hasClientResult = true
		client.CredentialBlob = &appwebauthn.CredentialBlobCreateOutput{Accepted: output.CredBlob}
	}
	if output != nil && output.CreateHMACSecretOutputs != nil && input != nil && input.CreateHMACSecretInputs != nil {
		hasClientResult = true
		client.HMACSecret = &appwebauthn.HMACSecretCreateOutput{Enabled: output.HMACCreateSecret}
	}
	if output != nil && output.CreateHMACSecretMCOutputs != nil {
		hasClientResult = true
		client.HMACSecretMC = hmacSecretOutput(output.CreateHMACSecretMCOutputs.HMACGetSecret)
	} else if input != nil && input.CreateHMACSecretMCInputs != nil && output != nil && output.CreatePRFOutputs != nil {
		hasClientResult = true
		client.HMACSecretMC = &appwebauthn.HMACSecretOutput{
			Output1Hex: hex.EncodeToString(output.PRF.Results.First),
			Output2Hex: hex.EncodeToString(output.PRF.Results.Second),
		}
	}
	if authenticatorOutput != nil && authenticatorOutput.CreateMinPinLengthOutput != nil {
		hasAuthenticatorOutput = true
		authenticator.MinPINLength = &appwebauthn.MinPINLengthOutput{
			Value: authenticatorOutput.CreateMinPinLengthOutput.MinPinLength,
		}
	}
	if authenticatorOutput != nil && authenticatorOutput.CreatePinComplexityPolicyOutput != nil {
		hasAuthenticatorOutput = true
		authenticator.PINComplexityPolicy = &appwebauthn.PINComplexityPolicyOutput{
			Enabled: authenticatorOutput.CreatePinComplexityPolicyOutput.PinComplexityPolicy,
		}
	}
	if input != nil && input.PRFInputs != nil {
		hasClientResult = true
		prf := &appwebauthn.MakeCredentialPRFOutput{}
		if output != nil && output.CreateHMACSecretOutputs != nil {
			prf.Enabled = output.HMACCreateSecret
		}
		if output != nil && output.CreatePRFOutputs != nil {
			prf.Enabled = output.PRF.Enabled
			if !input.PRF.Eval.IsZero() {
				prf.Results = prfOutputValues(output.PRF.Results)
			}
		}
		client.PRF = prf
	}
	if hasClientResult {
		result.Client = client
	}
	if hasAuthenticatorOutput {
		result.Authenticator = authenticator
	}
	if !hasClientResult && !hasAuthenticatorOutput {
		return nil
	}

	return result
}

func getAssertionExtensionResults(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	output *ctapwebauthn.GetAuthenticationExtensionsClientOutputs,
) *appwebauthn.GetAssertionExtensionResults {
	result := new(appwebauthn.GetAssertionClientExtensionResults)
	hasResult := false
	if output != nil && output.GetCredentialBlobOutputs != nil {
		hasResult = true
		result.CredentialBlob = &appwebauthn.CredentialBlobGetOutput{
			ValueHex: hex.EncodeToString(output.GetCredBlob),
		}
	}
	if output != nil && output.GetHMACSecretOutputs != nil {
		hasResult = true
		result.HMACSecret = hmacSecretOutput(output.GetHMACSecretOutputs.HMACGetSecret)
	}
	if input != nil && input.PRFInputs != nil {
		hasResult = true
		result.PRF = &appwebauthn.GetAssertionPRFOutput{}
		if output != nil && output.GetPRFOutputs != nil {
			result.PRF.Results = prfOutputValues(output.PRF.Results)
		}
	}
	if !hasResult {
		return nil
	}

	return &appwebauthn.GetAssertionExtensionResults{Client: result}
}

func hmacSecretOutput(output ctapwebauthn.HMACGetSecretOutput) *appwebauthn.HMACSecretOutput {
	return &appwebauthn.HMACSecretOutput{
		Output1Hex: hex.EncodeToString(output.Output1),
		Output2Hex: hex.EncodeToString(output.Output2),
	}
}

func prfOutputValues(
	output ctapwebauthn.AuthenticationExtensionsPRFValues,
) ctapwebauthn.AuthenticationExtensionsPRFValues {
	return ctapwebauthn.AuthenticationExtensionsPRFValues{
		First:  slices.Clone(output.First),
		Second: slices.Clone(output.Second),
	}
}
