package webauthn

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-ctap/ctap/credential"
)

func TestNormalizeMakeCredentialInputRequiresCoreFields(t *testing.T) {
	base := MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		User:           credential.PublicKeyCredentialUserEntity{ID: []byte{0x01, 0x02}},
		ClientDataJSON: []byte(`{"type":"webauthn.create"}`),
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{
			{Algorithm: -7},
		},
	}

	tests := []struct {
		name  string
		input MakeCredentialInput
	}{
		{
			name: "rp id",
			input: MakeCredentialInput{
				User:             base.User,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name: "user id",
			input: MakeCredentialInput{
				RP:               base.RP,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name: "client data",
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             base.User,
				PubKeyCredParams: base.PubKeyCredParams,
			},
		},
		{
			name: "params",
			input: MakeCredentialInput{
				RP:             base.RP,
				User:           base.User,
				ClientDataJSON: base.ClientDataJSON,
			},
		},
		{
			name: "algorithm",
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             base.User,
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: []credential.PublicKeyCredentialParameters{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeMakeCredentialInput(tt.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NormalizeMakeCredentialInput error = %v, want invalid input", err)
			}
		})
	}
}

func TestNormalizeInputsTrimCloneAndDefaultCredentialTypes(t *testing.T) {
	userID := []byte{0x0a, 0x0b}
	credentialID := []byte{0xc0, 0x5e}
	input, err := NormalizeMakeCredentialInput(MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: " example.com "},
		User:           credential.PublicKeyCredentialUserEntity{ID: userID},
		ClientDataJSON: []byte("client-data"),
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{
			{Algorithm: -7},
		},
		ExcludeList: []credential.PublicKeyCredentialDescriptor{
			{ID: credentialID},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeMakeCredentialInput: %v", err)
	}

	if input.RP.ID != "example.com" {
		t.Fatalf("RP.ID = %q, want trimmed", input.RP.ID)
	}

	if !bytes.Equal(input.User.ID, userID) || &input.User.ID[0] == &userID[0] {
		t.Fatalf("User.ID = %#v, want cloned user id", input.User.ID)
	}

	if input.PubKeyCredParams[0].Type != PublicKeyCredentialTypePublicKey {
		t.Fatalf("param type = %q, want public-key", input.PubKeyCredParams[0].Type)
	}

	if input.ExcludeList[0].Type != PublicKeyCredentialTypePublicKey ||
		!bytes.Equal(input.ExcludeList[0].ID, credentialID) ||
		&input.ExcludeList[0].ID[0] == &credentialID[0] {
		t.Fatalf("exclude descriptor = %#v, want default public-key with cloned id", input.ExcludeList[0])
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
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NormalizeGetAssertionInput error = %v, want invalid input", err)
	}
}
