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

func TestNormalizeHMACSecretInputClonesWithoutDuplicatingCTAPValidation(t *testing.T) {
	input := &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateHMACSecretMCInputs: &ctapwebauthn.CreateHMACSecretMCInputs{
			HMACGetSecret: ctapwebauthn.HMACGetSecretInput{
				Salt1: bytes.Repeat([]byte{0x11}, 31),
				Salt2: bytes.Repeat([]byte{0x22}, 33),
			},
		},
	}

	normalized := normalizeMakeCredentialExtensions(input)
	if normalized.CreateHMACSecretMCInputs == input.CreateHMACSecretMCInputs ||
		&normalized.HMACGetSecret.Salt1[0] == &input.HMACGetSecret.Salt1[0] {
		t.Fatal("normalized HMAC input aliases caller input")
	}
	if len(normalized.HMACGetSecret.Salt1) != 31 || len(normalized.HMACGetSecret.Salt2) != 33 {
		t.Fatalf("normalized HMAC input = %#v, want values preserved for ctap validation", normalized.HMACGetSecret)
	}
}

func TestNormalizeMakeCredentialPRF(t *testing.T) {
	t.Run("empty request is valid", func(t *testing.T) {
		input := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{})
		normalized := normalizeMakeCredentialExtensions(input)
		if normalized.PRFInputs == nil || normalized.PRFInputs == input.PRFInputs {
			t.Fatalf("normalized PRF = %#v, want cloned empty request", normalized.PRFInputs)
		}
	})

	t.Run("empty BufferSources remain present", func(t *testing.T) {
		input := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}, Second: []byte{}},
		})
		normalized := normalizeMakeCredentialExtensions(input)
		if normalized.PRF.Eval.First == nil || normalized.PRF.Eval.Second == nil {
			t.Fatalf("normalized PRF = %#v, want present-empty values", normalized.PRF)
		}
	})

	t.Run("ctap-owned combinations are preserved", func(t *testing.T) {
		raw := &ctapwebauthn.CreateHMACSecretMCInputs{
			HMACGetSecret: ctapwebauthn.HMACGetSecretInput{Salt1: make([]byte, 31)},
		}
		input := createPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{"id": {}},
		})
		input.CreateHMACSecretMCInputs = raw

		normalized := normalizeMakeCredentialExtensions(input)
		if normalized.CreateHMACSecretMCInputs == nil || normalized.PRF.EvalByCredential == nil {
			t.Fatalf("normalized extensions = %#v, want ctap-owned inputs preserved", normalized)
		}
	})
}

func TestNormalizeGetAssertionPRF(t *testing.T) {
	credentialID := []byte{0xaa, 0xbb}
	key := base64.RawURLEncoding.EncodeToString(credentialID)
	t.Run("empty request is valid", func(t *testing.T) {
		normalized := normalizeGetAssertionExtensions(
			getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{}))
		if normalized.PRFInputs == nil {
			t.Fatalf("normalized = %#v, want PRF input", normalized)
		}
	})

	t.Run("global and matching record are cloned", func(t *testing.T) {
		values := ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{0x01}, Second: []byte{0x02}}
		input := getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval:             values,
			EvalByCredential: map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{key: values},
		})
		normalized := normalizeGetAssertionExtensions(input)
		mapped := normalized.PRF.EvalByCredential[key]
		if &normalized.PRF.Eval.First[0] == &input.PRF.Eval.First[0] ||
			&mapped.Second[0] == &input.PRF.EvalByCredential[key].Second[0] {
			t.Fatal("normalized PRF values alias caller-owned values")
		}
	})

	t.Run("ctap-owned combinations are preserved", func(t *testing.T) {
		raw := &ctapwebauthn.GetHMACSecretInputs{
			HMACGetSecret: ctapwebauthn.HMACGetSecretInput{Salt1: make([]byte, 31)},
		}
		input := getPRFExtensions(ctapwebauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{"not+base64url": {}},
		})
		input.GetHMACSecretInputs = raw

		normalized := normalizeGetAssertionExtensions(input)
		if normalized.GetHMACSecretInputs == nil || normalized.PRF.EvalByCredential == nil {
			t.Fatalf("normalized extensions = %#v, want ctap-owned inputs preserved", normalized)
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
	supportedPreview, err := BuildMakeCredentialPreview(device, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	}, validMakeCredentialInput(makeExtensions))
	if err != nil {
		t.Fatalf("BuildMakeCredentialPreview with PRF support: %v", err)
	}
	for _, warning := range supportedPreview.Warnings {
		if warning.Code == "webauthn.extension.prf.not_advertised" {
			t.Fatalf("Make warnings = %#v, hmac-secret advertises PRF support", supportedPreview.Warnings)
		}
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

func TestBuildMakeCredentialPreviewDefersCredentialBlobLimitToCTAP(t *testing.T) {
	maximum := uint(3)
	preview, err := BuildMakeCredentialPreview(
		report.DeviceReport{},
		protocol.AuthenticatorGetInfoResponse{MaxCredBlobLength: &maximum},
		validMakeCredentialInput(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialBlobInputs: &ctapwebauthn.CreateCredentialBlobInputs{CredBlob: []byte("four")},
		}),
	)
	if err != nil {
		t.Fatalf("BuildMakeCredentialPreview: %v", err)
	}
	if got := string(preview.Input.Extensions.CredBlob); got != "four" {
		t.Fatalf("credential blob = %q, want preserved for ctap validation", got)
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
