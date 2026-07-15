package workflow

import (
	"encoding/base64"
	"testing"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
)

func TestCTAPMakeCredentialExtensionsKeepsRawInputsAndMapsCredProps(t *testing.T) {
	credProtect := &ctapwebauthn.CreateCredentialProtectionInputs{
		CredentialProtectionPolicy:        extension.CredentialProtectionPolicyUserVerificationRequired,
		EnforceCredentialProtectionPolicy: true,
	}
	credBlob := &ctapwebauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")}
	hmacCreate := &ctapwebauthn.CreateHMACSecretInputs{HMACCreateSecret: true}
	hmacMC := &ctapwebauthn.CreateHMACSecretMCInputs{
		HMACGetSecret: ctapwebauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
	}
	minPINLength := &ctapwebauthn.CreateMinPinLengthInputs{MinPinLength: true}
	complexity := &ctapwebauthn.CreatePinComplexityPolicyInputs{PinComplexityPolicy: true}

	got := ctapMakeCredentialExtensions(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateCredentialPropertiesInputs: &ctapwebauthn.CreateCredentialPropertiesInputs{CredentialProperties: true},
		CreateCredentialProtectionInputs: credProtect,
		CreateCredentialBlobInputs:       credBlob,
		CreateHMACSecretInputs:           hmacCreate,
		CreateHMACSecretMCInputs:         hmacMC,
		CreateMinPinLengthInputs:         minPINLength,
		CreatePinComplexityPolicyInputs:  complexity,
	}, protocol.AuthenticatorGetInfoResponse{})

	if got == nil || got.CreateCredentialPropertiesInputs == nil || !got.CredentialProperties ||
		got.CreateCredentialProtectionInputs != credProtect ||
		got.CreateCredentialBlobInputs != credBlob ||
		got.CreateHMACSecretInputs != hmacCreate ||
		got.CreateHMACSecretMCInputs != hmacMC ||
		got.CreateMinPinLengthInputs != minPINLength ||
		got.CreatePinComplexityPolicyInputs != complexity {
		t.Fatalf("CTAP create extensions = %#v, want raw inputs plus credProps:true", got)
	}
}

func TestCTAPMakeCredentialPRFUsesAvailableAuthenticatorExtension(t *testing.T) {
	evaluated := &ctapwebauthn.PRFInputs{
		PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}, Second: []byte{}},
		},
	}

	t.Run("availability request uses hmac-secret", func(t *testing.T) {
		got := ctapMakeCredentialExtensions(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &ctapwebauthn.PRFInputs{},
		}, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		})
		if got.CreateHMACSecretInputs == nil || !got.HMACCreateSecret || got.PRFInputs != nil {
			t.Fatalf("CTAP extensions = %#v, want hmac-secret enable", got)
		}
	})

	t.Run("registration evaluation uses hmac-secret-mc PRF", func(t *testing.T) {
		got := ctapMakeCredentialExtensions(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: evaluated},
			protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecretMC},
			})
		if got.PRFInputs == nil || got.PRF.Eval.Second == nil {
			t.Fatalf("CTAP extensions = %#v, want evaluated PRF with present-empty second", got)
		}
	})

	t.Run("hmac-secret fallback enables PRF without results", func(t *testing.T) {
		got := ctapMakeCredentialExtensions(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: evaluated},
			protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			})
		if got.CreateHMACSecretInputs == nil || !got.HMACCreateSecret || got.PRFInputs != nil {
			t.Fatalf("CTAP extensions = %#v, want hmac-secret fallback", got)
		}
	})

	t.Run("unsupported PRF is ignored", func(t *testing.T) {
		got := ctapMakeCredentialExtensions(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: evaluated},
			protocol.AuthenticatorGetInfoResponse{})
		if got.PRFInputs != nil || got.CreateHMACSecretInputs != nil {
			t.Fatalf("CTAP extensions = %#v, want ignored PRF", got)
		}
	})
}

func TestCTAPGetAssertionPRFUsesSingleAllowListOverride(t *testing.T) {
	credentialID := []byte{0xfb, 0xff, 0x00}
	input := &ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte("global")},
			EvalByCredential: map[string]ctapwebauthn.AuthenticationExtensionsPRFValues{
				base64.RawURLEncoding.EncodeToString(credentialID): {First: []byte("override")},
			},
		}},
	}
	got := ctapGetAssertionExtensions(input, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})

	key := base64.RawURLEncoding.EncodeToString(credentialID)
	if got == nil || got.PRFInputs == nil ||
		string(got.PRF.Eval.First) != "global" || len(got.PRF.EvalByCredential) != 1 ||
		string(got.PRF.EvalByCredential[key].First) != "override" {
		t.Fatalf("CTAP get PRF = %#v, want the normalized Level 3 PRF inputs", got)
	}
}

func TestCTAPGetAssertionEmptyAndUnsupportedPRFAreIgnored(t *testing.T) {
	empty := ctapGetAssertionExtensions(&ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{},
	}, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})
	if empty == nil || empty.PRFInputs != nil {
		t.Fatalf("empty PRF CTAP inputs = %#v, want no authenticator extension", empty)
	}

	unsupported := ctapGetAssertionExtensions(&ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{},
		}},
	}, protocol.AuthenticatorGetInfoResponse{})
	if unsupported == nil || unsupported.PRFInputs != nil {
		t.Fatalf("unsupported PRF CTAP inputs = %#v, want ignored extension", unsupported)
	}
}

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
			CreateCredProtectOutput:  &protocol.CreateCredProtectOutput{CredProtect: 0x03},
			CreateMinPinLengthOutput: &protocol.CreateMinPinLengthOutput{MinPinLength: 8},
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

func TestMakeCredentialPRFAlwaysReportsEnabledAndOnlyReturnsRequestedEvaluation(t *testing.T) {
	empty := makeCredentialExtensionResults(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{},
	}, protocol.AuthenticatorMakeCredentialResponse{})
	if empty == nil || empty.Client == nil || empty.Client.PRF == nil || empty.Client.PRF.Enabled ||
		!empty.Client.PRF.Results.IsZero() {
		t.Fatalf("unsupported PRF result = %#v, want {enabled:false}", empty)
	}

	output := protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{PRF: ctapwebauthn.CreateAuthenticationExtensionsPRFOutputs{
				Enabled: true,
				Results: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{0xaa}},
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
	input := &ctapwebauthn.GetAuthenticationExtensionsClientInputs{PRFInputs: &ctapwebauthn.PRFInputs{
		PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
		},
	}}
	got := getAssertionExtensionResults(input, &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
		GetPRFOutputs: &ctapwebauthn.GetPRFOutputs{PRF: ctapwebauthn.GetAuthenticationExtensionsPRFOutputs{
			Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
				First: []byte{0x07, 0x08},
			},
		}},
	})
	if got == nil || got.Client == nil || got.Client.PRF == nil ||
		len(got.Client.PRF.Results.First) != 2 {
		t.Fatalf("GetAssertion PRF result = %#v", got)
	}

	empty := getAssertionExtensionResults(&ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		PRFInputs: &ctapwebauthn.PRFInputs{},
	}, nil)
	if empty == nil || empty.Client == nil || empty.Client.PRF == nil || !empty.Client.PRF.Results.IsZero() {
		t.Fatalf("empty PRF result = %#v, want {prf:{}}", empty)
	}
}

func TestGetAssertionExtensionResultsKeepRawOutputs(t *testing.T) {
	got := getAssertionExtensionResults(nil, &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
		GetCredentialBlobOutputs: &ctapwebauthn.GetCredentialBlobOutputs{GetCredBlob: []byte{0x01, 0x02}},
		GetHMACSecretOutputs: &ctapwebauthn.GetHMACSecretOutputs{HMACGetSecret: ctapwebauthn.HMACGetSecretOutput{
			Output1: []byte{0x03, 0x04},
			Output2: []byte{0x05, 0x06},
		}},
	})
	if got == nil || got.Client == nil || got.Client.CredentialBlob == nil ||
		got.Client.CredentialBlob.ValueHex != "0102" || got.Client.HMACSecret == nil ||
		got.Client.HMACSecret.Output1Hex != "0304" || got.Client.HMACSecret.Output2Hex != "0506" {
		t.Fatalf("raw GetAssertion extension results = %#v", got)
	}
}
