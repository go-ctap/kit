package webauthn

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model/report"
	. "github.com/go-ctap/kit/model/webauthn"
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
	if got := makePreview.Warnings[3].Message; !strings.Contains(got, "does not advertise hmac-secret") ||
		!strings.Contains(got, "ignore unsupported extension inputs") {
		t.Fatalf("PRF warning = %q", got)
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

func TestBuildMakeCredentialPreviewWarnsAboutDiscoverableOverwrite(t *testing.T) {
	input := validMakeCredentialInput(nil)
	input.Options.ResidentKey = new(true)

	preview, err := BuildMakeCredentialPreview(
		report.DeviceReport{},
		protocol.AuthenticatorGetInfoResponse{},
		input,
	)
	if err != nil {
		t.Fatalf("BuildMakeCredentialPreview: %v", err)
	}

	if len(preview.Warnings) != 2 {
		t.Fatalf("Warnings = %#v, want mutation and overwrite warnings", preview.Warnings)
	}
	if got := preview.Warnings[1]; got.Code != "webauthn.make_credential.discoverable_overwrite" ||
		got.Severity != "destructive" || !strings.Contains(got.Message, "old credential ID stops resolving") {
		t.Fatalf("overwrite warning = %#v", got)
	}
}

func TestBuildMakeCredentialPreviewDefersCredentialBlobLimitToCTAP(t *testing.T) {
	preview, err := BuildMakeCredentialPreview(
		report.DeviceReport{},
		protocol.AuthenticatorGetInfoResponse{MaxCredBlobLength: 3},
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
