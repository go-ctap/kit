package workflow

import (
	"context"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	rtwebauthn "github.com/go-ctap/kit/internal/webauthn"
	"github.com/go-ctap/kit/model/failure"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
	"github.com/samber/lo"
)

func (r Runner) MakeCredential(
	ctx context.Context,
	device authenticator.WebAuthnManager,
	req appwebauthn.MakeCredentialOperation,
) (appwebauthn.MakeCredentialOutput, error) {
	var output appwebauthn.MakeCredentialOutput

	input, err := rtwebauthn.NormalizeMakeCredentialInput(req.MakeCredentialInput)
	if err != nil {
		return output, err
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return output, err
	}
	preview, err := rtwebauthn.BuildMakeCredentialPreview(r.env.Selected, info, input)
	if err != nil {
		return output, err
	}
	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	var response protocol.AuthenticatorMakeCredentialResponse
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionMakeCredential,
		RPID:       input.RP.ID,
		Optional:   true,
	}, func(token []byte) error {
		var err error
		response, err = r.callMakeCredential(ctx, device, token, input)

		return err
	})
	if err != nil {
		if response.AuthData != nil && response.AuthData.AttestedCredentialData != nil {
			if result, resultErr := makeCredentialResult(r.env.Selected.Fingerprint, input.RP.ID, input.Extensions, response); resultErr == nil {
				output.Result = &result
				r.afterUserPresence(result.UserPresent)
			}
		}

		return output, annotateMakeCredentialError(err)
	}
	result, err := makeCredentialResult(r.env.Selected.Fingerprint, input.RP.ID, input.Extensions, response)
	if err != nil {
		return output, err
	}
	output.Result = &result
	r.afterUserPresence(result.UserPresent)

	return output, nil
}

func (r Runner) GetAssertion(
	ctx context.Context,
	device authenticator.WebAuthnManager,
	req appwebauthn.GetAssertionOperation,
) (appwebauthn.GetAssertionOutput, error) {
	var output appwebauthn.GetAssertionOutput

	input, err := rtwebauthn.NormalizeGetAssertionInput(req.GetAssertionInput)
	if err != nil {
		return output, err
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return output, err
	}
	preview, err := rtwebauthn.BuildGetAssertionPreview(r.env.Selected, info, input)
	if err != nil {
		return output, err
	}
	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	result := appwebauthn.GetAssertionResult{
		DeviceFingerprint: r.env.Selected.Fingerprint,
		RPID:              input.RPID,
	}

	readAssertions := func(token []byte) error {
		var index uint
		for response, err := range device.GetAssertion(
			ctx,
			token,
			input.RPID,
			input.ClientDataJSON,
			input.AllowList,
			input.Extensions,
			ctapAuthenticatorOptions(input.Options, token != nil),
		) {
			if err != nil {
				return annotateGetAssertionError(err)
			}

			result.Assertions = append(result.Assertions, assertionResult(index, response))
			index++
		}

		return nil
	}

	if err := r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionGetAssertion,
		RPID:       input.RPID,
		Optional:   true,
	}, readAssertions); err != nil {
		return output, err
	}

	output.Result = &result
	for _, assertion := range result.Assertions {
		if assertion.UserPresent {
			r.afterUserPresence(true)

			break
		}
	}

	return output, nil
}

func (r Runner) afterUserPresence(present bool) {
	if present {
		r.env.Tokens.InvalidateUnlessPermission(protocol.PermissionLargeBlobWrite)
	}
}

func (r Runner) callMakeCredential(
	ctx context.Context,
	device authenticator.WebAuthnManager,
	token []byte,
	input appwebauthn.MakeCredentialInput,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return device.MakeCredential(
		ctx,
		token,
		input.ClientDataJSON,
		input.RP,
		input.User,
		input.PubKeyCredParams,
		input.ExcludeList,
		input.Extensions,
		ctapAuthenticatorOptions(input.Options, token != nil),
		input.EnterpriseAttestation,
		input.AttestationFormatsPreference,
	)
}

func annotateMakeCredentialError(err error) error {
	return errornorm.Annotate(err, errornorm.WithCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorMakeCredential,
	))
}

func annotateGetAssertionError(err error) error {
	return errornorm.Annotate(err, errornorm.WithCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorGetAssertion,
	))
}

func makeCredentialResult(
	fingerprint string,
	rpID string,
	extensions *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorMakeCredentialResponse,
) (appwebauthn.MakeCredentialResult, error) {
	if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil {
		return appwebauthn.MakeCredentialResult{}, failure.New(failure.CodeAttestedCredentialDataMissing,
			failure.WithPhase(failure.PhaseDecode),
		)
	}

	publicKeyCOSE, err := cbor.Marshal(response.AuthData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return appwebauthn.MakeCredentialResult{}, errornorm.Annotate(
			err,
			errornorm.WithPhase(failure.PhaseDecode),
		)
	}

	attestationObjectCBOR, err := attestationObjectCBOR(response)
	if err != nil {
		return appwebauthn.MakeCredentialResult{}, errornorm.Annotate(
			err,
			errornorm.WithPhase(failure.PhaseDecode),
		)
	}

	return appwebauthn.MakeCredentialResult{
		DeviceFingerprint:        fingerprint,
		RPID:                     rpID,
		Format:                   response.Format,
		CredentialIDHex:          hex.EncodeToString(response.AuthData.AttestedCredentialData.CredentialID),
		PublicKeyCOSEHex:         hex.EncodeToString(publicKeyCOSE),
		AuthenticatorDataHex:     hex.EncodeToString(response.AuthDataRaw),
		AttestationObjectCBORHex: hex.EncodeToString(attestationObjectCBOR),
		AAGUID:                   response.AuthData.AttestedCredentialData.AAGUID.String(),
		SignCount:                response.AuthData.SignCount,
		UserPresent:              response.AuthData.Flags.UserPresent(),
		UserVerified:             response.AuthData.Flags.UserVerified(),
		EnterpriseAttestation:    response.EnterpriseAttestation,
		ExtensionResults:         makeCredentialExtensionResults(extensions, response),
	}, nil
}

func attestationObjectCBOR(response protocol.AuthenticatorMakeCredentialResponse) ([]byte, error) {
	attestationStatement := response.AttestationStatement
	if attestationStatement == nil {
		attestationStatement = map[string]any{}
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	return encMode.Marshal(map[string]any{
		"fmt":      response.Format,
		"authData": response.AuthDataRaw,
		"attStmt":  attestationStatement,
	})
}

func assertionResult(
	index uint,
	response protocol.AuthenticatorGetAssertionResponse,
) appwebauthn.Assertion {
	assertion := appwebauthn.Assertion{
		Index:                index,
		Credential:           response.Credential,
		AuthenticatorDataHex: hex.EncodeToString(response.AuthDataRaw),
		SignatureHex:         hex.EncodeToString(response.Signature),
		NumberOfCredentials:  response.NumberOfCredentials,
		UserSelected:         response.UserSelected,
		ExtensionResults:     getAssertionExtensionResults(response),
	}

	if response.AuthData != nil {
		assertion.SignCount = response.AuthData.SignCount
		assertion.UserPresent = response.AuthData.Flags.UserPresent()
		assertion.UserVerified = response.AuthData.Flags.UserVerified()
	}

	if response.User != nil {
		assertion.User = response.User
	}

	return assertion
}

func ctapAuthenticatorOptions(options appwebauthn.AuthenticatorOptions, withToken bool) map[protocol.Option]bool {
	out := make(map[protocol.Option]bool)
	if options.ResidentKey != nil {
		out[protocol.OptionResidentKeys] = lo.FromPtr(options.ResidentKey)
	}

	if options.UserPresence != nil {
		out[protocol.OptionUserPresence] = lo.FromPtr(options.UserPresence)
	}

	if options.UserVerification != nil && !withToken {
		out[protocol.OptionUserVerification] = lo.FromPtr(options.UserVerification)
	}

	if len(out) == 0 {
		return nil
	}

	return out
}
