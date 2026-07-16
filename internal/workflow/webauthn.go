package workflow

import (
	"context"
	"encoding/hex"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
	"github.com/samber/lo"
)

func (r Runner) makeCredential(ctx context.Context, req model.MakeCredentialOperation) (model.MakeCredentialOutput, error) {
	var output model.MakeCredentialOutput

	input, err := appwebauthn.NormalizeMakeCredentialInput(req.MakeCredentialInput)
	if err != nil {
		return output, err
	}

	preview, err := appwebauthn.BuildMakeCredentialPreview(r.env.Selected, r.infoProvider().GetInfo(), input)
	if err != nil {
		return output, err
	}
	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Create WebAuthn credential for " + input.RP.ID + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	if makeCredentialNeedsToken(r.infoProvider().GetInfo(), input) {
		token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionMakeCredential, input.RP.ID)
		if err != nil {
			return output, err
		}
		defer secret.Zero(token)

		response, err := r.callMakeCredential(ctx, token, input)
		if err != nil {
			return output, annotateMakeCredentialError(err)
		}

		result, err := makeCredentialResult(r.env.Selected.Fingerprint, input.RP.ID, input.Extensions, response)
		if err != nil {
			return output, err
		}
		output.Result = &result

		return output, nil
	}

	response, err := r.callMakeCredential(ctx, nil, input)
	if err != nil {
		return output, annotateMakeCredentialError(err)
	}
	result, err := makeCredentialResult(r.env.Selected.Fingerprint, input.RP.ID, input.Extensions, response)
	if err != nil {
		return output, err
	}
	output.Result = &result

	return output, nil
}

func (r Runner) getAssertion(ctx context.Context, req model.GetAssertionOperation) (model.GetAssertionOutput, error) {
	var output model.GetAssertionOutput

	input, err := appwebauthn.NormalizeGetAssertionInput(req.GetAssertionInput)
	if err != nil {
		return output, err
	}
	info := r.infoProvider().GetInfo()
	preview, err := appwebauthn.BuildGetAssertionPreview(r.env.Selected, info, input)
	if err != nil {
		return output, err
	}
	output.Preview = preview
	if req.DryRun {
		return output, nil
	}

	tokenRequired := lo.FromPtr(input.Options.UserVerification) ||
		info.Options[protocol.OptionAlwaysUv] ||
		input.Extensions != nil && prfHasEvaluation(input.Extensions.PRFInputs) &&
			slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret)

	result := appwebauthn.GetAssertionResult{
		DeviceFingerprint: r.env.Selected.Fingerprint,
		RPID:              input.RPID,
	}

	readAssertions := func(token []byte) error {
		var index uint
		for response, err := range r.webAuthnManager().GetAssertion(
			ctx,
			token,
			input.RPID,
			input.ClientDataJSON,
			input.AllowList,
			ctapGetAssertionExtensions(input.Extensions, info),
			ctapAuthenticatorOptions(input.Options, token != nil),
		) {
			if err != nil {
				return annotateGetAssertionError(err)
			}

			result.Assertions = append(result.Assertions, assertionResult(index, input.Extensions, response))
			index++
		}

		return nil
	}
	if tokenRequired {
		token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionGetAssertion, input.RPID)
		if err != nil {
			return output, err
		}
		defer secret.Zero(token)

		if err := readAssertions(token); err != nil {
			return output, err
		}
	} else if err := readAssertions(nil); err != nil {
		return output, err
	}

	output.Result = &result

	return output, nil
}

func (r Runner) callMakeCredential(
	ctx context.Context,
	token []byte,
	input appwebauthn.MakeCredentialInput,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return r.webAuthnManager().MakeCredential(
		ctx,
		token,
		input.ClientDataJSON,
		input.RP,
		input.User,
		input.PubKeyCredParams,
		input.ExcludeList,
		ctapMakeCredentialExtensions(input.Extensions, r.infoProvider().GetInfo()),
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

func makeCredentialNeedsToken(
	info protocol.AuthenticatorGetInfoResponse,
	input appwebauthn.MakeCredentialInput,
) bool {
	if lo.FromPtr(input.Options.UserVerification) {
		return true
	}
	if input.Extensions != nil && input.Extensions.PRFInputs != nil && !input.Extensions.PRF.Eval.IsZero() &&
		slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC) {
		return true
	}

	notRequired, ok := info.Options[protocol.OptionMakeCredentialUvNotRequired]

	return !ok || !notRequired
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
	extensions *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorGetAssertionResponse,
) appwebauthn.Assertion {
	assertion := appwebauthn.Assertion{
		Index:                index,
		Credential:           response.Credential,
		AuthenticatorDataHex: hex.EncodeToString(response.AuthDataRaw),
		SignatureHex:         hex.EncodeToString(response.Signature),
		ExtensionResults:     getAssertionExtensionResults(extensions, response.ExtensionOutputs),
	}
	if response.NumberOfCredentials != nil {
		assertion.NumberOfCredentials = snapshotPtr(response.NumberOfCredentials)
	}
	if response.UserSelected != nil {
		assertion.UserSelected = snapshotPtr(response.UserSelected)
	}

	if response.AuthData != nil {
		assertion.SignCount = response.AuthData.SignCount
		assertion.UserPresent = response.AuthData.Flags.UserPresent()
		assertion.UserVerified = response.AuthData.Flags.UserVerified()
	}

	if response.User != nil {
		user := *response.User
		user.ID = append([]byte(nil), response.User.ID...)
		assertion.User = &user
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
