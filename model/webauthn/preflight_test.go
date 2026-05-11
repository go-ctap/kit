package webauthn

import (
	"errors"
	"testing"
)

func TestNormalizeMakeCredentialInputRequiresCoreFields(t *testing.T) {
	base := MakeCredentialInput{
		RP:             RelyingParty{ID: "example.com"},
		User:           User{IDHex: "0102"},
		ClientDataJSON: []byte(`{"type":"webauthn.create"}`),
		PubKeyCredParams: []CredentialParameter{
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
				PubKeyCredParams: []CredentialParameter{{}},
			},
		},
		{
			name: "invalid user id hex",
			input: MakeCredentialInput{
				RP:               base.RP,
				User:             User{IDHex: "not-hex"},
				ClientDataJSON:   base.ClientDataJSON,
				PubKeyCredParams: base.PubKeyCredParams,
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

func TestNormalizeInputsNormalizeHexAndDefaultCredentialTypes(t *testing.T) {
	input, err := NormalizeMakeCredentialInput(MakeCredentialInput{
		RP:             RelyingParty{ID: " example.com "},
		User:           User{IDHex: "0A0B"},
		ClientDataJSON: []byte("client-data"),
		PubKeyCredParams: []CredentialParameter{
			{Algorithm: -7},
		},
		ExcludeList: []CredentialDescriptor{
			{IDHex: "C05E"},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeMakeCredentialInput: %v", err)
	}

	if input.RP.ID != "example.com" {
		t.Fatalf("RP.ID = %q, want trimmed", input.RP.ID)
	}

	if input.User.IDHex != "0a0b" {
		t.Fatalf("User.IDHex = %q, want normalized lower-case hex", input.User.IDHex)
	}

	if input.PubKeyCredParams[0].Type != PublicKeyCredentialTypePublicKey {
		t.Fatalf("param type = %q, want public-key", input.PubKeyCredParams[0].Type)
	}

	if input.ExcludeList[0].Type != PublicKeyCredentialTypePublicKey ||
		input.ExcludeList[0].IDHex != "c05e" {
		t.Fatalf("exclude descriptor = %#v, want normalized public-key/c05e", input.ExcludeList[0])
	}
}

func TestNormalizeGetAssertionInputValidatesAllowList(t *testing.T) {
	_, err := NormalizeGetAssertionInput(GetAssertionInput{
		RPID:           "example.com",
		ClientDataJSON: []byte("client-data"),
		AllowList: []CredentialDescriptor{
			{IDHex: "xyz"},
		},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NormalizeGetAssertionInput error = %v, want invalid credential id", err)
	}
}
