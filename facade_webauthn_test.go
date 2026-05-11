package ctapkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"maps"
	"slices"
	"testing"

	"github.com/go-ctap/ctaphid/pkg/ctaphid"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
	"github.com/go-ctap/kit/transport"
	"github.com/google/uuid"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/samber/lo"
)

func TestMakeCredentialDryRunDoesNotConfirmAcquireTokenOrMutate(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.Run(context.Background(), sampleMakeCredentialOperation(true), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	result := output.(model.MakeCredentialOutput)
	if result.Result != nil {
		t.Fatalf("dry-run result = %#v, want nil", result.Result)
	}
	if result.Preview.RP.ID != "example.com" {
		t.Fatalf("preview RP = %#v", result.Preview.RP)
	}
	if a.makeCredentialCalls != 0 {
		t.Fatalf("MakeCredential calls = %d, want 0", a.makeCredentialCalls)
	}
	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want none", a.tokenRPIDs)
	}
}

func TestMakeCredentialMapsRequestAndUsesRawClientDataJSON(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	uv := true
	rk := false
	op := sampleMakeCredentialOperation(false)
	op.Confirmed = true
	op.Options = appwebauthn.AuthenticatorOptions{
		ResidentKey:      &rk,
		UserVerification: &uv,
	}
	op.ExcludeList = []appwebauthn.CredentialDescriptor{
		{IDHex: "C05E", Transports: []string{"usb"}},
	}

	_, err := session.Run(context.Background(), op, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !bytes.Equal(a.makeCredentialClientData, op.ClientDataJSON) {
		t.Fatalf("clientDataJSON = %q, want raw %q", a.makeCredentialClientData, op.ClientDataJSON)
	}
	if a.makeCredentialRP.ID != "example.com" || !bytes.Equal(a.makeCredentialUser.ID, []byte{0x01, 0x02}) {
		t.Fatalf("mapped rp/user = %#v %#v", a.makeCredentialRP, a.makeCredentialUser)
	}
	if len(a.makeCredentialParams) != 1 || a.makeCredentialParams[0].Algorithm != -7 {
		t.Fatalf("mapped params = %#v", a.makeCredentialParams)
	}
	if len(a.makeCredentialExcludeList) != 1 ||
		!bytes.Equal(a.makeCredentialExcludeList[0].ID, []byte{0xc0, 0x5e}) ||
		a.makeCredentialExcludeList[0].Transports[0] != webauthntypes.AuthenticatorTransportUSB {
		t.Fatalf("mapped excludeList = %#v", a.makeCredentialExcludeList)
	}
	wantOptions := map[ctaptypes.Option]bool{
		ctaptypes.OptionResidentKeys:     false,
		ctaptypes.OptionUserVerification: true,
	}
	if !maps.Equal(a.makeCredentialOptions, wantOptions) {
		t.Fatalf("options = %#v, want %#v", a.makeCredentialOptions, wantOptions)
	}
	if !slices.Equal(a.tokenRPIDs, []string{"example.com"}) {
		t.Fatalf("token rpIDs = %v, want scoped RP ID", a.tokenRPIDs)
	}
}

func TestMakeCredentialSkipsTokenWhenAuthenticatorDoesNotRequireIt(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	op := sampleMakeCredentialOperation(false)
	op.Confirmed = true
	if _, err := session.Run(context.Background(), op, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want none", a.tokenRPIDs)
	}
	if string(a.makeCredentialToken) != "" {
		t.Fatalf("MakeCredential token = %q, want none", a.makeCredentialToken)
	}
}

func TestMakeCredentialInvalidatesCredentialCaches(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("first ListCredentials: %v", err)
	}
	if _, err := session.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("cached ListCredentials: %v", err)
	}
	if got := a.metadataCalls; got != 1 {
		t.Fatalf("metadata calls before mutation = %d, want 1", got)
	}

	op := sampleMakeCredentialOperation(false)
	op.Confirmed = true
	if _, err := session.Run(context.Background(), op, nil); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	if _, err := session.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("post-mutation ListCredentials: %v", err)
	}
	if got := a.metadataCalls; got != 2 {
		t.Fatalf("metadata calls after mutation = %d, want 2", got)
	}
}

func TestGetAssertionReturnsAllAssertionsInOrder(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output, err := session.Run(context.Background(), model.GetAssertionOperation{
		GetAssertionInput: appwebauthn.GetAssertionInput{
			RPID:           "example.com",
			ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
			AllowList: []appwebauthn.CredentialDescriptor{
				{IDHex: "C05E"},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	result := output.(model.GetAssertionOutput).Result
	if len(result.Assertions) != 2 {
		t.Fatalf("assertions = %#v, want 2", result.Assertions)
	}
	if result.Assertions[0].Credential.IDHex != "c05e" ||
		result.Assertions[1].Credential.IDHex != "b0b0" {
		t.Fatalf("assertion order = %#v", result.Assertions)
	}
	if result.Assertions[0].SignatureHex != "aabb" ||
		result.Assertions[1].User.IDHex != "757365722d32" {
		t.Fatalf("assertion mapping = %#v", result.Assertions)
	}
	if !bytes.Equal(a.getAssertionClientData, []byte(`{"type":"webauthn.get"}`)) {
		t.Fatalf("getAssertion clientDataJSON = %q", a.getAssertionClientData)
	}
	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want none without UV option", a.tokenRPIDs)
	}
}

func TestGetAssertionAcquiresScopedTokenWhenUVRequested(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	uv := true
	_, err := session.Run(context.Background(), model.GetAssertionOperation{
		GetAssertionInput: appwebauthn.GetAssertionInput{
			RPID:           "example.com",
			ClientDataJSON: []byte("client-data"),
			Options: appwebauthn.AuthenticatorOptions{
				UserVerification: &uv,
			},
		},
	}, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !slices.Equal(a.tokenRPIDs, []string{"example.com"}) {
		t.Fatalf("token rpIDs = %v, want scoped RP ID", a.tokenRPIDs)
	}
	if string(a.getAssertionToken) != "token:example.com" {
		t.Fatalf("GetAssertion token = %q, want scoped token", a.getAssertionToken)
	}
}

func TestWebAuthnCTAPStatusMapsSentinels(t *testing.T) {
	tests := []struct {
		name      string
		operation model.Operation
		setupErr  func(*webauthnTestAuthenticator)
		want      error
	}{
		{
			name: "make credential excluded",
			operation: model.MakeCredentialOperation{
				MakeCredentialInput: sampleMakeCredentialOperation(false).MakeCredentialInput,
				Confirmed:           true,
			},
			setupErr: func(a *webauthnTestAuthenticator) {
				a.makeCredentialErr = &ctaphid.CTAPError{
					Command:    ctaptypes.AuthenticatorMakeCredential,
					StatusCode: ctaphid.CTAP2_ERR_CREDENTIAL_EXCLUDED,
				}
			},
			want: appcredentials.ErrCredentialExcluded,
		},
		{
			name: "get assertion no credentials",
			operation: model.GetAssertionOperation{
				GetAssertionInput: appwebauthn.GetAssertionInput{
					RPID:           "example.com",
					ClientDataJSON: []byte("client-data"),
				},
			},
			setupErr: func(a *webauthnTestAuthenticator) {
				a.getAssertionErr = &ctaphid.CTAPError{
					Command:    ctaptypes.AuthenticatorGetAssertion,
					StatusCode: ctaphid.CTAP2_ERR_NO_CREDENTIALS,
				}
			},
			want: appcredentials.ErrCredentialNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
			tt.setupErr(a)
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			_, err := session.Run(context.Background(), tt.operation, nil)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Run error = %v, want sentinel %v", err, tt.want)
			}
			if !model.IsErrorCategory(err, model.ErrorInvalidState) {
				t.Fatalf("Run category = %v, want invalid-state", err)
			}
		})
	}
}

func TestWebAuthnOutputsDoNotMarshalTokens(t *testing.T) {
	output := model.GetAssertionOutput{
		Result: appwebauthn.GetAssertionResult{
			Assertions: []appwebauthn.Assertion{
				{SignatureHex: "746f6b656e"},
			},
		},
	}

	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("pinUvAuthToken")) {
		t.Fatalf("WebAuthn output leaked token marker: %s", raw)
	}
}

func sampleMakeCredentialOperation(dryRun bool) model.MakeCredentialOperation {
	return model.MakeCredentialOperation{
		MakeCredentialInput: appwebauthn.MakeCredentialInput{
			RP: appwebauthn.RelyingParty{
				ID:   "example.com",
				Name: "Example",
			},
			User: appwebauthn.User{
				IDHex:       "0102",
				Name:        "alice@example.com",
				DisplayName: "Alice",
			},
			ClientDataJSON: []byte(`{"type":"webauthn.create"}`),
			PubKeyCredParams: []appwebauthn.CredentialParameter{
				{Algorithm: -7},
			},
		},
		DryRun: dryRun,
	}
}

type webauthnTestAuthenticator struct {
	contractAuthenticator
	makeCredentialUvNotRequired bool
	tokenRPIDs                  []string

	makeCredentialCalls       int
	makeCredentialErr         error
	makeCredentialToken       []byte
	makeCredentialClientData  []byte
	makeCredentialRP          webauthntypes.PublicKeyCredentialRpEntity
	makeCredentialUser        webauthntypes.PublicKeyCredentialUserEntity
	makeCredentialParams      []webauthntypes.PublicKeyCredentialParameters
	makeCredentialExcludeList []webauthntypes.PublicKeyCredentialDescriptor
	makeCredentialOptions     map[ctaptypes.Option]bool

	getAssertionErr        error
	getAssertionToken      []byte
	getAssertionClientData []byte

	metadataCalls int
}

func (a *webauthnTestAuthenticator) GetInfo() ctaptypes.AuthenticatorGetInfoResponse {
	return ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionCredentialManagement:        true,
			ctaptypes.OptionPinUvAuthToken:              true,
			ctaptypes.OptionUserVerification:            true,
			ctaptypes.OptionMakeCredentialUvNotRequired: a.makeCredentialUvNotRequired,
		},
	}
}

func (a *webauthnTestAuthenticator) GetPinUvAuthTokenUsingUV(
	_ ctaptypes.Permission,
	rpID string,
) ([]byte, error) {
	a.tokenRPIDs = append(a.tokenRPIDs, rpID)

	return []byte("token:" + rpID), nil
}

func (a *webauthnTestAuthenticator) MakeCredential(
	pinUvAuthToken []byte,
	clientData []byte,
	rp webauthntypes.PublicKeyCredentialRpEntity,
	user webauthntypes.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthntypes.PublicKeyCredentialParameters,
	excludeList []webauthntypes.PublicKeyCredentialDescriptor,
	_ *webauthntypes.CreateAuthenticationExtensionsClientInputs,
	options map[ctaptypes.Option]bool,
	_ uint,
	_ []webauthntypes.AttestationStatementFormatIdentifier,
) (ctaptypes.AuthenticatorMakeCredentialResponse, error) {
	a.makeCredentialCalls++
	a.makeCredentialToken = append([]byte(nil), pinUvAuthToken...)
	a.makeCredentialClientData = append([]byte(nil), clientData...)
	a.makeCredentialRP = rp
	a.makeCredentialUser = user
	a.makeCredentialParams = append([]webauthntypes.PublicKeyCredentialParameters(nil), pubKeyCredParams...)
	a.makeCredentialExcludeList = append([]webauthntypes.PublicKeyCredentialDescriptor(nil), excludeList...)
	if options != nil {
		a.makeCredentialOptions = lo.Assign(options)
	}
	if a.makeCredentialErr != nil {
		return ctaptypes.AuthenticatorMakeCredentialResponse{}, a.makeCredentialErr
	}

	return sampleMakeCredentialResponse(), nil
}

func (a *webauthnTestAuthenticator) GetAssertion(
	pinUvAuthToken []byte,
	_ string,
	clientData []byte,
	_ []webauthntypes.PublicKeyCredentialDescriptor,
	_ *webauthntypes.GetAuthenticationExtensionsClientInputs,
	_ map[ctaptypes.Option]bool,
) iter.Seq2[ctaptypes.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorGetAssertionResponse, error) bool) {
		a.getAssertionToken = append([]byte(nil), pinUvAuthToken...)
		a.getAssertionClientData = append([]byte(nil), clientData...)
		if a.getAssertionErr != nil {
			yield(ctaptypes.AuthenticatorGetAssertionResponse{}, a.getAssertionErr)

			return
		}
		if !yield(sampleAssertionResponse([]byte{0xc0, 0x5e}, []byte{0xaa, 0xbb}, []byte("user-1"), 2), nil) {
			return
		}

		yield(sampleAssertionResponse([]byte{0xb0, 0xb0}, []byte{0xcc, 0xdd}, []byte("user-2"), 0), nil)
	}
}

func (a *webauthnTestAuthenticator) GetCredsMetadata(
	[]byte,
) (ctaptypes.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls++

	return ctaptypes.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             1,
		MaxPossibleRemainingResidentCredentialsCount: 8,
	}, nil
}

func (a *webauthnTestAuthenticator) EnumerateRPs(
	[]byte,
) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(ctaptypes.AuthenticatorCredentialManagementResponse{
			RP:       webauthntypes.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *webauthnTestAuthenticator) EnumerateCredentials(
	[]byte,
	[]byte,
) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(ctaptypes.AuthenticatorCredentialManagementResponse{
			User: webauthntypes.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "alice@example.com",
				DisplayName: "Alice",
			},
			CredentialID: webauthntypes.PublicKeyCredentialDescriptor{
				Type: webauthntypes.PublicKeyCredentialTypePublicKey,
				ID:   []byte{0xc0, 0x5e},
			},
			TotalCredentials: 1,
		}, nil)
	}
}

func sampleMakeCredentialResponse() ctaptypes.AuthenticatorMakeCredentialResponse {
	return ctaptypes.AuthenticatorMakeCredentialResponse{
		Format:      webauthntypes.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: []byte{0x01, 0x02, 0x03},
		AuthData: &ctaptypes.MakeCredentialAuthData{
			Flags:     ctaptypes.AuthDataFlagUserPresent | ctaptypes.AuthDataFlagUserVerified,
			SignCount: 7,
			AttestedCredentialData: &ctaptypes.AttestedCredentialData{
				AAGUID:       uuid.Must(uuid.Parse("00112233-4455-6677-8899-aabbccddeeff")),
				CredentialID: []byte{0xc0, 0x5e},
				CredentialPublicKey: key.Key{
					iana.KeyParameterKty:    iana.KeyTypeEC2,
					iana.KeyParameterAlg:    iana.AlgorithmES256,
					iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
					iana.EC2KeyParameterX:   []byte{0x01},
					iana.EC2KeyParameterY:   []byte{0x02},
				},
			},
		},
		AttestationStatement: map[string]any{
			"alg": int64(-7),
			"sig": []byte{0x99},
		},
	}
}

func sampleAssertionResponse(
	credentialID []byte,
	signature []byte,
	userID []byte,
	numberOfCredentials uint,
) ctaptypes.AuthenticatorGetAssertionResponse {
	return ctaptypes.AuthenticatorGetAssertionResponse{
		Credential: webauthntypes.PublicKeyCredentialDescriptor{
			Type:       webauthntypes.PublicKeyCredentialTypePublicKey,
			ID:         credentialID,
			Transports: []webauthntypes.AuthenticatorTransport{webauthntypes.AuthenticatorTransportUSB},
		},
		AuthDataRaw: []byte{0x05, 0x06},
		AuthData: &ctaptypes.GetAssertionAuthData{
			Flags:     ctaptypes.AuthDataFlagUserPresent,
			SignCount: 9,
		},
		Signature:           signature,
		User:                &webauthntypes.PublicKeyCredentialUserEntity{ID: userID, Name: string(userID)},
		NumberOfCredentials: numberOfCredentials,
	}
}
