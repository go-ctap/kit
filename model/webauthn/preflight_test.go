package webauthn

import (
	"bytes"
	"slices"
	"testing"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/kit/model/failure"
)

func TestNormalizeMakeCredentialInputRequiresCoreFields(t *testing.T) {
	userPresenceFalse := false
	base := MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		User:           credential.PublicKeyCredentialUserEntity{ID: []byte{0x01, 0x02}},
		ClientDataJSON: []byte(`{"type":"webauthn.create"}`),
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{
			{Algorithm: -7},
		},
	}

	tests := []struct {
		name     string
		input    MakeCredentialInput
		wantCode failure.Code
	}{
		{
			name:     "rp id",
			wantCode: failure.CodeRelyingPartyIDRequired,
			input: MakeCredentialInput{
				User:             base.User,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name:     "user id",
			wantCode: failure.CodeUserIDRequired,
			input: MakeCredentialInput{
				RP:               base.RP,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name:     "client data",
			wantCode: failure.CodeClientDataJSONRequired,
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             base.User,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name:     "params",
			wantCode: failure.CodePublicKeyCredentialParametersRequired,
			input: MakeCredentialInput{
				RP:             base.RP,
				User:           base.User,
				ClientDataJSON: base.ClientDataJSON,
			},
		},
		{
			name:     "algorithm",
			wantCode: failure.CodePublicKeyCredentialAlgorithmRequired,
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             base.User,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: []credential.PublicKeyCredentialParameters{{}},
			},
		},
		{
			name:     "user id length",
			wantCode: failure.CodeCTAPLengthInvalid,
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             credential.PublicKeyCredentialUserEntity{ID: bytes.Repeat([]byte{0x01}, 65)},
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name:     "duplicate parameter",
			wantCode: failure.CodeCTAPParameterInvalid,
			input: MakeCredentialInput{
				RP:             base.RP,
				User:           base.User,
				ClientDataJSON: base.ClientDataJSON,
				PubKeyCredParams: []credential.PublicKeyCredentialParameters{
					{Algorithm: -7},
					{Algorithm: -7},
				},
			},
		},
		{
			name:     "false user presence",
			wantCode: failure.CodeCTAPOptionInvalid,
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             base.User,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
				Options:          AuthenticatorOptions{UserPresence: &userPresenceFalse},
			},
		},
		{
			name:     "enterprise attestation",
			wantCode: failure.CodeCTAPOptionInvalid,
			input: MakeCredentialInput{
				RP:                    base.RP,
				User:                  base.User,
				ClientDataJSON:        base.ClientDataJSON,
				PubKeyCredParams:      base.PubKeyCredParams,
				EnterpriseAttestation: 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeMakeCredentialInput(tt.input)
			if !failure.IsCode(err, tt.wantCode) {
				t.Fatalf("NormalizeMakeCredentialInput error = %v, want %s", err, tt.wantCode)
			}

			if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
				t.Fatalf("NormalizeMakeCredentialInput phase = %q, want %q", got, failure.PhaseValidation)
			}
		})
	}
}

func TestNormalizeInputsTrimAndDefaultCredentialTypes(t *testing.T) {
	userID := []byte{0x0a, 0x0b}
	credentialID := []byte{0xc0, 0x5e}
	formats := []attestation.AttestationStatementFormatIdentifier{
		attestation.AttestationStatementFormatIdentifierPacked,
		attestation.AttestationStatementFormatIdentifierPacked,
		attestation.AttestationStatementFormatIdentifierNone,
	}
	input, err := NormalizeMakeCredentialInput(MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: " example.com "},
		User:           credential.PublicKeyCredentialUserEntity{ID: userID},
		ClientDataJSON: []byte("client-data"),
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{
			{Algorithm: -7},
			{Type: "future-key", Algorithm: -7},
		},
		ExcludeList: []credential.PublicKeyCredentialDescriptor{
			{ID: credentialID},
		},
		AttestationFormatsPreference: formats,
	})
	if err != nil {
		t.Fatalf("NormalizeMakeCredentialInput: %v", err)
	}

	if input.RP.ID != "example.com" {
		t.Fatalf("RP.ID = %q, want trimmed", input.RP.ID)
	}

	if !bytes.Equal(input.User.ID, userID) {
		t.Fatalf("User.ID = %#v, want original user id", input.User.ID)
	}

	if input.PubKeyCredParams[0].Type != PublicKeyCredentialTypePublicKey {
		t.Fatalf("param type = %q, want public-key", input.PubKeyCredParams[0].Type)
	}

	if input.PubKeyCredParams[1].Type != "future-key" {
		t.Fatalf("param type = %q, want future-key", input.PubKeyCredParams[1].Type)
	}

	if input.ExcludeList[0].Type != PublicKeyCredentialTypePublicKey ||
		!bytes.Equal(input.ExcludeList[0].ID, credentialID) {
		t.Fatalf("exclude descriptor = %#v, want default public-key with original id", input.ExcludeList[0])
	}

	if !slices.Equal(input.AttestationFormatsPreference, formats) {
		t.Fatalf("attestation formats = %#v, want original formats", input.AttestationFormatsPreference)
	}
}

func TestNormalizeGetAssertionInputValidatesAllowListID(t *testing.T) {
	_, err := NormalizeGetAssertionInput(GetAssertionInput{
		RPID:           "example.com",
		ClientDataJSON: []byte("client-data"),
		AllowList: []credential.PublicKeyCredentialDescriptor{
			{},
		},
	})
	if !failure.IsCode(err, failure.CodeCredentialIDRequired) {
		t.Fatalf("NormalizeGetAssertionInput error = %v, want %s", err, failure.CodeCredentialIDRequired)
	}

	if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
		t.Fatalf("NormalizeGetAssertionInput phase = %q, want %q", got, failure.PhaseValidation)
	}
}

func TestNormalizeGetAssertionInputRequiresCoreFields(t *testing.T) {
	tests := []struct {
		name     string
		input    GetAssertionInput
		wantCode failure.Code
	}{
		{
			name: "rp id",
			input: GetAssertionInput{
				ClientDataJSON: []byte("client-data"),
			},
			wantCode: failure.CodeRelyingPartyIDRequired,
		},
		{
			name: "client data",
			input: GetAssertionInput{
				RPID: "example.com",
			},
			wantCode: failure.CodeClientDataJSONRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeGetAssertionInput(tt.input)
			if !failure.IsCode(err, tt.wantCode) {
				t.Fatalf("NormalizeGetAssertionInput error = %v, want %s", err, tt.wantCode)
			}

			if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
				t.Fatalf("NormalizeGetAssertionInput phase = %q, want %q", got, failure.PhaseValidation)
			}
		})
	}
}
