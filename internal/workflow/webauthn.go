package workflow

import (
	"context"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
	"github.com/ldclabs/cose/key"
	"github.com/samber/lo"
)

func (r Runner) makeCredential(ctx context.Context, req model.MakeCredentialOperation) (model.MakeCredentialOutput, error) {
	var output model.MakeCredentialOutput

	input, err := appwebauthn.NormalizeMakeCredentialInput(req.MakeCredentialInput)
	if err != nil {
		return output, err
	}

	preview, err := appwebauthn.BuildMakeCredentialPreview(r.env.Selected, input)
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
		declinedErr:     appwebauthn.ErrConfirmationRequired,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	if makeCredentialNeedsToken(r.infoProvider().GetInfo(), input) {
		token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), ctaptypes.PermissionMakeCredential, input.RP.ID)
		if err != nil {
			return output, annotateMakeCredentialError(err)
		}
		defer secret.Zero(token)

		response, err := r.callMakeCredential(token, input)
		if err != nil {
			return output, annotateMakeCredentialError(err)
		}

		result, err := makeCredentialResult(r.env.Selected.DeviceID, input.RP.ID, response)
		if err != nil {
			return output, err
		}
		output.Result = &result

		return output, nil
	}

	response, err := r.callMakeCredential(nil, input)
	if err != nil {
		return output, annotateMakeCredentialError(err)
	}

	result, err := makeCredentialResult(r.env.Selected.DeviceID, input.RP.ID, response)
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

	var tokenRequired bool
	if lo.FromPtr(input.Options.UserVerification) {
		tokenRequired = true
	}

	result := appwebauthn.GetAssertionResult{
		DeviceID: r.env.Selected.DeviceID,
		RPID:     input.RPID,
	}

	readAssertions := func(token []byte) error {
		var index uint
		for response, err := range r.webAuthnManager().GetAssertion(
			token,
			input.RPID,
			input.ClientDataJSON,
			ctapCredentialDescriptors(input.AllowList),
			nil,
			ctapAuthenticatorOptions(input.Options),
		) {
			if err != nil {
				return annotateGetAssertionError(err)
			}

			result.Assertions = append(result.Assertions, assertionResult(index, response))
			index++
		}

		return nil
	}
	if tokenRequired {
		token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), ctaptypes.PermissionGetAssertion, input.RPID)
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

	output.Result = result

	return output, nil
}

func (r Runner) callMakeCredential(
	token []byte,
	input appwebauthn.MakeCredentialInput,
) (ctaptypes.AuthenticatorMakeCredentialResponse, error) {
	return r.webAuthnManager().MakeCredential(
		token,
		input.ClientDataJSON,
		ctapRelyingParty(input.RP),
		ctapUser(input.User),
		lo.Map(input.PubKeyCredParams, func(param appwebauthn.CredentialParameter, _ int) webauthntypes.PublicKeyCredentialParameters {
			return webauthntypes.PublicKeyCredentialParameters{
				Type:      webauthntypes.PublicKeyCredentialType(param.Type),
				Algorithm: key.Alg(param.Algorithm),
			}
		}),
		ctapCredentialDescriptors(input.ExcludeList),
		nil,
		ctapAuthenticatorOptions(input.Options),
		0,
		nil,
	)
}

func annotateMakeCredentialError(err error) error {
	return ctaperrors.Annotate(err, ctaperrors.WithCommand(
		model.OperationMakeCredential,
		ctaptypes.AuthenticatorMakeCredential,
		ctaperrors.DomainCredentials,
	))
}

func annotateGetAssertionError(err error) error {
	return ctaperrors.Annotate(err, ctaperrors.WithCommand(
		model.OperationGetAssertion,
		ctaptypes.AuthenticatorGetAssertion,
		ctaperrors.DomainCredentials,
	))
}

func makeCredentialNeedsToken(
	info ctaptypes.AuthenticatorGetInfoResponse,
	input appwebauthn.MakeCredentialInput,
) bool {
	if lo.FromPtr(input.Options.UserVerification) {
		return true
	}

	notRequired, ok := info.Options[ctaptypes.OptionMakeCredentialUvNotRequired]

	return !ok || !notRequired
}

func makeCredentialResult(
	deviceID string,
	rpID string,
	response ctaptypes.AuthenticatorMakeCredentialResponse,
) (appwebauthn.MakeCredentialResult, error) {
	if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil {
		return appwebauthn.MakeCredentialResult{}, appwebauthn.ErrAttestedCredentialDataMissing
	}

	publicKeyCOSE, err := cbor.Marshal(response.AuthData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return appwebauthn.MakeCredentialResult{}, err
	}

	attestationObjectCBOR, err := attestationObjectCBOR(response)
	if err != nil {
		return appwebauthn.MakeCredentialResult{}, err
	}

	return appwebauthn.MakeCredentialResult{
		DeviceID:                 deviceID,
		RPID:                     rpID,
		Format:                   string(response.Format),
		CredentialIDHex:          hex.EncodeToString(response.AuthData.AttestedCredentialData.CredentialID),
		PublicKeyCOSEHex:         hex.EncodeToString(publicKeyCOSE),
		AuthenticatorDataHex:     hex.EncodeToString(response.AuthDataRaw),
		AttestationObjectCBORHex: hex.EncodeToString(attestationObjectCBOR),
		AAGUID:                   response.AuthData.AttestedCredentialData.AAGUID.String(),
		SignCount:                response.AuthData.SignCount,
		UserPresent:              response.AuthData.Flags.UserPresent(),
		UserVerified:             response.AuthData.Flags.UserVerified(),
		EnterpriseAttestation:    response.EnterpriseAttestation,
	}, nil
}

func attestationObjectCBOR(response ctaptypes.AuthenticatorMakeCredentialResponse) ([]byte, error) {
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

func assertionResult(index uint, response ctaptypes.AuthenticatorGetAssertionResponse) appwebauthn.Assertion {
	assertion := appwebauthn.Assertion{
		Index:                index,
		Credential:           publicCredentialDescriptor(response.Credential),
		AuthenticatorDataHex: hex.EncodeToString(response.AuthDataRaw),
		SignatureHex:         hex.EncodeToString(response.Signature),
		NumberOfCredentials:  response.NumberOfCredentials,
		UserSelected:         response.UserSelected,
	}

	if response.AuthData != nil {
		assertion.SignCount = response.AuthData.SignCount
		assertion.UserPresent = response.AuthData.Flags.UserPresent()
		assertion.UserVerified = response.AuthData.Flags.UserVerified()
	}

	if response.User != nil {
		assertion.User = &appwebauthn.User{
			IDHex:       hex.EncodeToString(response.User.ID),
			Name:        response.User.Name,
			DisplayName: response.User.DisplayName,
		}
	}

	return assertion
}

func ctapRelyingParty(rp appwebauthn.RelyingParty) webauthntypes.PublicKeyCredentialRpEntity {
	return webauthntypes.PublicKeyCredentialRpEntity{
		ID:   rp.ID,
		Name: rp.Name,
	}
}

func ctapUser(user appwebauthn.User) webauthntypes.PublicKeyCredentialUserEntity {
	userID, _ := hex.DecodeString(user.IDHex)

	return webauthntypes.PublicKeyCredentialUserEntity{
		ID:          userID,
		Name:        user.Name,
		DisplayName: user.DisplayName,
	}
}

func ctapCredentialDescriptors(
	descriptors []appwebauthn.CredentialDescriptor,
) []webauthntypes.PublicKeyCredentialDescriptor {
	return lo.Map(descriptors, func(descriptor appwebauthn.CredentialDescriptor, _ int) webauthntypes.PublicKeyCredentialDescriptor {
		id, _ := hex.DecodeString(descriptor.IDHex)
		var transports []webauthntypes.AuthenticatorTransport
		if len(descriptor.Transports) > 0 {
			transports = lo.Map(descriptor.Transports, func(transport string, _ int) webauthntypes.AuthenticatorTransport {
				return webauthntypes.AuthenticatorTransport(transport)
			})
		}

		return webauthntypes.PublicKeyCredentialDescriptor{
			Type:       webauthntypes.PublicKeyCredentialType(descriptor.Type),
			ID:         id,
			Transports: transports,
		}
	})
}

func publicCredentialDescriptor(
	descriptor webauthntypes.PublicKeyCredentialDescriptor,
) appwebauthn.CredentialDescriptor {
	return appwebauthn.CredentialDescriptor{
		Type:       string(descriptor.Type),
		IDHex:      hex.EncodeToString(descriptor.ID),
		Transports: credentialTransports(descriptor.Transports),
	}
}

func ctapAuthenticatorOptions(options appwebauthn.AuthenticatorOptions) map[ctaptypes.Option]bool {
	out := make(map[ctaptypes.Option]bool)
	if options.ResidentKey != nil {
		out[ctaptypes.OptionResidentKeys] = lo.FromPtr(options.ResidentKey)
	}
	if options.UserPresence != nil {
		out[ctaptypes.OptionUserPresence] = lo.FromPtr(options.UserPresence)
	}
	if options.UserVerification != nil {
		out[ctaptypes.OptionUserVerification] = lo.FromPtr(options.UserVerification)
	}

	if len(out) == 0 {
		return nil
	}

	return out
}
