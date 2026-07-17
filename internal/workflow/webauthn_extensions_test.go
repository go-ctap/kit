package workflow

import (
	"testing"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
)

func TestMakeCredentialExtensionResultsKeepRawOutputsAndMapLevel3Results(t *testing.T) {
	residentKey := false
	input := &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateCredentialPropertiesInputs: &ctapwebauthn.CreateCredentialPropertiesInputs{CredentialProperties: true},
		CreateCredentialBlobInputs:       &ctapwebauthn.CreateCredentialBlobInputs{},
		CreateHMACSecretInputs:           &ctapwebauthn.CreateHMACSecretInputs{},
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
		}},
	}
	response := protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreateCredentialPropertiesOutputs: &ctapwebauthn.CreateCredentialPropertiesOutputs{
				CredentialProperties: ctapwebauthn.CredentialPropertiesOutput{ResidentKey: &residentKey},
			},
			CreateCredentialBlobOutputs: &ctapwebauthn.CreateCredentialBlobOutputs{CredBlob: true},
			CreateHMACSecretOutputs:     &ctapwebauthn.CreateHMACSecretOutputs{HMACCreateSecret: true},
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{PRF: ctapwebauthn.CreateAuthenticationExtensionsPRFOutputs{
				Enabled: true,
				Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
					First:  []byte{0x01, 0x02},
					Second: []byte{0x03, 0x04},
				},
			}},
		},
		AuthData: &protocol.MakeCredentialAuthData{Extensions: &protocol.CreateExtensionOutputs{
			CreateCredProtectOutput:  protocol.CreateCredProtectOutput{CredProtect: 0x03},
			CreateMinPinLengthOutput: protocol.CreateMinPinLengthOutput{MinPinLength: 8},
			CreatePinComplexityPolicyOutput: &protocol.CreatePinComplexityPolicyOutput{
				PinComplexityPolicy: true,
			},
		}},
	}

	got := makeCredentialExtensionResults(input, response)
	if got == nil || got.Client == nil || got.Authenticator == nil {
		t.Fatalf("extension results = %#v, want client and authenticator sections", got)
	}
	if got.Client.CredentialProperties == nil || got.Client.CredentialProperties.ResidentKey == nil ||
		*got.Client.CredentialProperties.ResidentKey || got.Client.CredentialBlob == nil ||
		!got.Client.CredentialBlob.Accepted || got.Client.HMACSecret == nil ||
		!got.Client.HMACSecret.Enabled {
		t.Fatalf("client raw/credProps results = %#v", got.Client)
	}
	if got.Client.PRF == nil || !got.Client.PRF.Enabled ||
		len(got.Client.PRF.Results.First) != 2 || len(got.Client.PRF.Results.Second) != 2 {
		t.Fatalf("PRF result = %#v", got.Client.PRF)
	}
	if got.Authenticator.CredentialProtection == nil ||
		got.Authenticator.CredentialProtection.Policy != extension.CredentialProtectionPolicyUserVerificationRequired ||
		got.Authenticator.MinPINLength == nil || got.Authenticator.MinPINLength.Value != 8 ||
		got.Authenticator.PINComplexityPolicy == nil || !got.Authenticator.PINComplexityPolicy.Enabled {
		t.Fatalf("authenticator extension results = %#v", got.Authenticator)
	}
}

func TestMakeCredentialPRFUsesCTAPClientOutput(t *testing.T) {
	empty := makeCredentialExtensionResults(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{},
	}, protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{},
		},
	})
	if empty == nil || empty.Client == nil || empty.Client.PRF == nil || empty.Client.PRF.Enabled ||
		!empty.Client.PRF.Results.IsZero() {
		t.Fatalf("unsupported PRF result = %#v, want {enabled:false}", empty)
	}

	output := protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{PRF: ctapwebauthn.CreateAuthenticationExtensionsPRFOutputs{
				Enabled: true,
			}},
		},
	}
	availability := makeCredentialExtensionResults(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{},
	}, output)
	if availability.Client.PRF == nil || !availability.Client.PRF.Enabled ||
		!availability.Client.PRF.Results.IsZero() {
		t.Fatalf("availability PRF result = %#v, want enabled without results", availability)
	}
}

func TestMakeCredentialExtensionResultsStillRoutesRawHMACMC(t *testing.T) {
	response := protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{PRF: ctapwebauthn.CreateAuthenticationExtensionsPRFOutputs{
				Enabled: true,
				Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
					First:  []byte{0xaa},
					Second: []byte{0xbb},
				},
			}},
		},
	}
	raw := makeCredentialExtensionResults(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateHMACSecretMCInputs: &ctapwebauthn.CreateHMACSecretMCInputs{},
	}, response)
	if raw == nil || raw.Client == nil || raw.Client.HMACSecretMC == nil ||
		raw.Client.HMACSecretMC.Output1Hex != "aa" || raw.Client.HMACSecretMC.Output2Hex != "bb" ||
		raw.Client.PRF != nil {
		t.Fatalf("raw HMAC MC result = %#v", raw)
	}
}

func TestGetAssertionExtensionResultsUseLevel3PRFOutputWithoutEnabled(t *testing.T) {
	got := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
		GetPRFOutputs: &ctapwebauthn.GetPRFOutputs{PRF: ctapwebauthn.GetAuthenticationExtensionsPRFOutputs{
			Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
				First: []byte{0x07, 0x08},
			},
		}},
	}})
	if got == nil || got.Client == nil || got.Client.PRF == nil ||
		len(got.Client.PRF.Results.First) != 2 {
		t.Fatalf("GetAssertion PRF result = %#v", got)
	}

	empty := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
		GetPRFOutputs: &ctapwebauthn.GetPRFOutputs{},
	}})
	if empty == nil || empty.Client == nil || empty.Client.PRF == nil || !empty.Client.PRF.Results.IsZero() {
		t.Fatalf("empty PRF result = %#v, want {prf:{}}", empty)
	}
}

func TestGetAssertionExtensionResultsKeepRawOutputs(t *testing.T) {
	got := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
		GetCredentialBlobOutputs: &ctapwebauthn.GetCredentialBlobOutputs{GetCredBlob: []byte{0x01, 0x02}},
		GetHMACSecretOutputs: &ctapwebauthn.GetHMACSecretOutputs{HMACGetSecret: ctapwebauthn.HMACGetSecretOutput{
			Output1: []byte{0x03, 0x04},
			Output2: []byte{0x05, 0x06},
		}},
	}})
	if got == nil || got.Client == nil || got.Client.CredentialBlob == nil ||
		got.Client.CredentialBlob.ValueHex != "0102" || got.Client.HMACSecret == nil ||
		got.Client.HMACSecret.Output1Hex != "0304" || got.Client.HMACSecret.Output2Hex != "0506" {
		t.Fatalf("raw GetAssertion extension results = %#v", got)
	}
}

func TestWebAuthnLargeBlobOutputsPreserveOptionalPresence(t *testing.T) {
	unsupported := false
	makeResult := makeCredentialExtensionResults(nil, protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			LargeBlobOutputs: &ctapwebauthn.LargeBlobOutputs{LargeBlob: ctapwebauthn.AuthenticationExtensionsLargeBlobOutputs{
				Supported: &unsupported,
			}},
		},
	})
	if makeResult == nil || makeResult.Client == nil || makeResult.Client.LargeBlob == nil ||
		makeResult.Client.LargeBlob.Supported {
		t.Fatalf("make largeBlob output = %#v, want explicit false", makeResult)
	}

	written := false
	getResult := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{
		ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
			LargeBlobOutputs: &ctapwebauthn.LargeBlobOutputs{LargeBlob: ctapwebauthn.AuthenticationExtensionsLargeBlobOutputs{
				Blob:    []byte{},
				Written: &written,
			}},
		},
		AuthData: &protocol.GetAssertionAuthData{Extensions: &protocol.GetExtensionOutputs{
			GetThirdPartyPaymentOutput: &protocol.GetThirdPartyPaymentOutput{ThirdPartyPayment: false},
		}},
	})
	if getResult == nil || getResult.Client == nil || getResult.Client.LargeBlob == nil ||
		getResult.Client.LargeBlob.BlobHex == nil || *getResult.Client.LargeBlob.BlobHex != "" ||
		getResult.Client.LargeBlob.Written == nil || *getResult.Client.LargeBlob.Written ||
		getResult.Authenticator == nil || getResult.Authenticator.ThirdPartyPayment == nil ||
		*getResult.Authenticator.ThirdPartyPayment {
		t.Fatalf("get extension output = %#v, want present-empty blob and explicit false outputs", getResult)
	}
}
