package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
)

func TestWebAuthnExtensionJSONUsesLevel3Shapes(t *testing.T) {
	input := ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateCredentialPropertiesInputs: &ctapwebauthn.CreateCredentialPropertiesInputs{
			CredentialProperties: true,
		},
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
		}},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"credProps":true`, `"prf":{"eval":{"first":"Zmlyc3Q="}}`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("JSON = %s, want %s", raw, want)
		}
	}
}

func TestNormalizeHMACSecretSaltLengths(t *testing.T) {
	tests := []struct {
		name    string
		salt1   int
		salt2   int
		wantErr bool
	}{
		{name: "salt1 31", salt1: 31, wantErr: true},
		{name: "salt1 32", salt1: 32},
		{name: "salt1 33", salt1: 33, wantErr: true},
		{name: "salt2 31", salt1: 32, salt2: 31, wantErr: true},
		{name: "salt2 32", salt1: 32, salt2: 32},
		{name: "salt2 33", salt1: 32, salt2: 33, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
				CreateHMACSecretMCInputs: &ctapwebauthn.CreateHMACSecretMCInputs{
					HMACGetSecret: ctapwebauthn.HMACGetSecretInput{
						Salt1: bytes.Repeat([]byte{0x11}, tt.salt1),
						Salt2: bytes.Repeat([]byte{0x22}, tt.salt2),
					},
				},
			}

			normalized, err := normalizeMakeCredentialExtensions(input)
			if tt.wantErr {
				if !failure.IsCode(err, failure.CodeWebAuthnSecretSaltLengthInvalid) {
					t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnSecretSaltLengthInvalid)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMakeCredentialExtensions: %v", err)
			}
			if normalized.CreateHMACSecretMCInputs == input.CreateHMACSecretMCInputs ||
				&normalized.HMACGetSecret.Salt1[0] == &input.HMACGetSecret.Salt1[0] {
				t.Fatal("normalized HMAC input aliases caller input")
			}
		})
	}
}

func TestNormalizeMakeCredentialPRF(t *testing.T) {
	t.Run("empty request is valid", func(t *testing.T) {
		input := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{})
		normalized, err := normalizeMakeCredentialExtensions(input)
		if err != nil {
			t.Fatalf("normalizeMakeCredentialExtensions: %v", err)
		}
		if normalized.PRFInputs == nil || normalized.PRFInputs == input.PRFInputs {
			t.Fatalf("normalized PRF = %#v, want cloned empty request", normalized.PRFInputs)
		}
	})

	t.Run("empty BufferSources remain present", func(t *testing.T) {
		input := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}, Second: []byte{}},
		})
		normalized, err := normalizeMakeCredentialExtensions(input)
		if err != nil {
			t.Fatalf("normalizeMakeCredentialExtensions: %v", err)
		}
		if normalized.PRF.Eval.First == nil || normalized.PRF.Eval.Second == nil {
			t.Fatalf("normalized PRF = %#v, want present-empty values", normalized.PRF)
		}
	})

	t.Run("credential map is forbidden during registration", func(t *testing.T) {
		for _, values := range []map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{
			{},
			{"id": {}},
		} {
			_, err := normalizeMakeCredentialExtensions(createPRFExtensions(
				ctapwebauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: values},
			))
			if !failure.IsCode(err, failure.CodeWebAuthnPRFEvaluationInvalid) {
				t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnPRFEvaluationInvalid)
			}
		}
	})

	t.Run("raw hmac-secret-mc conflicts only with evaluated PRF", func(t *testing.T) {
		raw := &ctapwebauthn.CreateHMACSecretMCInputs{
			HMACGetSecret: ctapwebauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
		}
		empty := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{})
		empty.CreateHMACSecretMCInputs = raw
		if _, err := normalizeMakeCredentialExtensions(empty); err != nil {
			t.Fatalf("empty PRF with raw hmac-secret-mc: %v", err)
		}

		evaluated := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
		})
		evaluated.CreateHMACSecretMCInputs = raw
		_, err := normalizeMakeCredentialExtensions(evaluated)
		if !failure.IsCode(err, failure.CodeWebAuthnExtensionConflict) {
			t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnExtensionConflict)
		}
	})

	t.Run("raw hmac-secret false conflicts with PRF", func(t *testing.T) {
		input := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{})
		input.CreateHMACSecretInputs = &ctapwebauthn.CreateHMACSecretInputs{}
		_, err := normalizeMakeCredentialExtensions(input)
		if !failure.IsCode(err, failure.CodeWebAuthnExtensionConflict) {
			t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnExtensionConflict)
		}

		input.CreateHMACSecretInputs.HMACCreateSecret = true
		if _, err := normalizeMakeCredentialExtensions(input); err != nil {
			t.Fatalf("hmac-secret true with PRF: %v", err)
		}
	})
}

func TestNormalizeGetAssertionPRF(t *testing.T) {
	credentialID := []byte{0xaa, 0xbb}
	key := base64.RawURLEncoding.EncodeToString(credentialID)
	allowList := []credential.PublicKeyCredentialDescriptor{{ID: credentialID}}

	t.Run("empty request is valid", func(t *testing.T) {
		normalized, err := normalizeGetAssertionExtensions(
			getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{}), nil)
		if err != nil || normalized.PRFInputs == nil {
			t.Fatalf("normalized = %#v, error = %v", normalized, err)
		}
	})

	t.Run("global and matching record are cloned", func(t *testing.T) {
		values := ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{0x01}, Second: []byte{0x02}}
		input := getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval:             values,
			EvalByCredential: map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{key: values},
		})
		normalized, err := normalizeGetAssertionExtensions(input, allowList)
		if err != nil {
			t.Fatalf("normalizeGetAssertionExtensions: %v", err)
		}
		mapped := normalized.PRF.EvalByCredential[key]
		if &normalized.PRF.Eval.First[0] == &input.PRF.Eval.First[0] ||
			&mapped.Second[0] == &input.PRF.EvalByCredential[key].Second[0] {
			t.Fatal("normalized PRF values alias caller-owned values")
		}
	})

	tests := []struct {
		name string
		key  string
		list []credential.PublicKeyCredentialDescriptor
	}{
		{name: "padded key", key: base64.URLEncoding.EncodeToString(credentialID), list: allowList},
		{name: "malformed key", key: "not+base64url", list: allowList},
		{name: "empty key", key: "", list: allowList},
		{name: "unmatched key", key: key},
		{
			name: "multiple allowed credentials",
			key:  key,
			list: []credential.PublicKeyCredentialDescriptor{{ID: credentialID}, {ID: []byte{0xcc}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizeGetAssertionExtensions(getPRFExtensions(
				ctapwebauthn.AuthenticationExtensionsPRFInputs{
					EvalByCredential: map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{tt.key: {}},
				},
			), tt.list)
			if !failure.IsCode(err, failure.CodeWebAuthnPRFEvaluationInvalid) {
				t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnPRFEvaluationInvalid)
			}
		})
	}

	t.Run("raw hmac-secret conflicts only with evaluated PRF", func(t *testing.T) {
		raw := &ctapwebauthn.GetHMACSecretInputs{
			HMACGetSecret: ctapwebauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
		}
		empty := getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{})
		empty.GetHMACSecretInputs = raw
		if _, err := normalizeGetAssertionExtensions(empty, nil); err != nil {
			t.Fatalf("empty PRF with raw hmac-secret: %v", err)
		}

		evaluated := getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
		})
		evaluated.GetHMACSecretInputs = raw
		_, err := normalizeGetAssertionExtensions(evaluated, nil)
		if !failure.IsCode(err, failure.CodeWebAuthnExtensionConflict) {
			t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnExtensionConflict)
		}
	})
}

func TestBuildWebAuthnPreviewsKeepRawWarningsAndPRFSemantics(t *testing.T) {
	device := report.DeviceReport{Fingerprint: "device-1"}
	info := protocol.AuthenticatorGetInfoResponse{}
	makeExtensions := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
		Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
	})
	makeExtensions.CreateCredentialProtectionInputs = &ctapwebauthn.CreateCredentialProtectionInputs{
		CredentialProtectionPolicy: extension.CredentialProtectionPolicyUserVerificationOptional,
	}
	makeExtensions.CreateCredentialBlobInputs = &ctapwebauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")}
	makePreview, err := BuildMakeCredentialPreview(device, info, validMakeCredentialInput(makeExtensions))
	if err != nil {
		t.Fatalf("BuildMakeCredentialPreview: %v", err)
	}
	if len(makePreview.Warnings) != 4 || makePreview.Warnings[3].Code != "webauthn.extension.prf.not_advertised" {
		t.Fatalf("Make warnings = %#v, want mutation plus raw and PRF warnings", makePreview.Warnings)
	}

	getPreview, err := BuildGetAssertionPreview(device, info, GetAssertionInput{
		RPID:           "example.com",
		ClientDataJSON: []byte("client-data"),
		Extensions:     getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{}),
	})
	if err != nil {
		t.Fatalf("BuildGetAssertionPreview: %v", err)
	}
	if len(getPreview.Warnings) != 0 {
		t.Fatalf("Get warnings = %#v, want no warning for an empty PRF request", getPreview.Warnings)
	}
}

func TestBuildMakeCredentialPreviewValidatesReportedCredentialBlobMaximum(t *testing.T) {
	maximum := uint(3)
	_, err := BuildMakeCredentialPreview(
		report.DeviceReport{},
		protocol.AuthenticatorGetInfoResponse{MaxCredBlobLength: &maximum},
		validMakeCredentialInput(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialBlobInputs: &ctapwebauthn.CreateCredentialBlobInputs{CredBlob: []byte("four")},
		}),
	)
	if !failure.IsCode(err, failure.CodeWebAuthnExtensionInputInvalid) {
		t.Fatalf("error = %v, want %s", err, failure.CodeWebAuthnExtensionInputInvalid)
	}
}

func createPRFExtensions(
	input ctapwebauthn.AuthenticationExtensionsPRFInputs,
) *ctapwebauthn.CreateAuthenticationExtensionsClientInputs {
	return &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: input},
	}
}

func getPRFExtensions(
	input ctapwebauthn.AuthenticationExtensionsPRFInputs,
) *ctapwebauthn.GetAuthenticationExtensionsClientInputs {
	return &ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: input},
	}
}

func validMakeCredentialInput(
	extensions *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
) MakeCredentialInput {
	return MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		User:           credential.PublicKeyCredentialUserEntity{ID: []byte{0x01}},
		ClientDataJSON: []byte("client-data"),
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{
			{Algorithm: -7},
		},
		Extensions: extensions,
	}
}
