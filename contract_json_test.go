package ctapkit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/webauthn"
	"github.com/ldclabs/cose/key"
)

func TestOperationEventStagesHaveCountsWithoutPercent(t *testing.T) {
	completed := uint64(1)
	total := uint64(3)
	event := model.OperationEvent{
		Stage:     model.OperationStageEnumeratingRPs,
		Completed: &completed,
		Total:     &total,
	}

	if event.Stage != model.OperationStageEnumeratingRPs {
		t.Fatalf("unexpected stage: %s", event.Stage)
	}

	if event.Completed == nil || *event.Completed != 1 {
		t.Fatalf("unexpected completed count: %#v", event.Completed)
	}
}

func TestOperationEventIncludesStateStages(t *testing.T) {
	stages := []model.OperationStage{
		model.OperationStageCapturingBioSample,
	}
	for _, stage := range stages {
		if stage == "" {
			t.Fatal("stage must not be empty")
		}
	}
}

func TestWebAuthnOperationKindStrings(t *testing.T) {
	if got := (model.MakeCredentialOperation{}).Kind(); got != "webauthn.makeCredential" {
		t.Fatalf("MakeCredential kind = %q", got)
	}

	if got := (model.GetAssertionOperation{}).Kind(); got != "webauthn.getAssertion" {
		t.Fatalf("GetAssertion kind = %q", got)
	}
}

func TestUserVerificationInteractionJSON(t *testing.T) {
	raw, err := json.Marshal(model.InteractionRequest{
		Kind:       model.InteractionKindUserVerification,
		Permission: "credentialManagement",
	})
	if err != nil {
		t.Fatalf("marshal interaction request: %v", err)
	}

	if !strings.Contains(string(raw), `"kind":"user-verification"`) {
		t.Fatalf("user-verification JSON contract missing: %s", raw)
	}

	flow, err := json.Marshal(model.VerificationFlowPIN)
	if err != nil {
		t.Fatalf("marshal verification flow: %v", err)
	}

	if string(flow) != `"pin"` {
		t.Fatalf("verification flow JSON = %s, want pin", flow)
	}

	if strings.Contains(string(raw), "operationId") {
		t.Fatalf("operationId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), "sessionId") {
		t.Fatalf("sessionId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), "interactionId") {
		t.Fatalf("interactionId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), `"status"`) {
		t.Fatalf("status leaked into interaction request JSON: %s", raw)
	}
}

func TestTouchInteractionJSON(t *testing.T) {
	raw, err := json.Marshal(model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator",
		Destructive: true,
	})
	if err != nil {
		t.Fatalf("marshal interaction request: %v", err)
	}

	if !strings.Contains(string(raw), `"kind":"touch"`) {
		t.Fatalf("touch JSON contract missing: %s", raw)
	}

	if strings.Contains(string(raw), "operationId") {
		t.Fatalf("operationId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), "sessionId") || strings.Contains(string(raw), "interactionId") {
		t.Fatalf("runtime correlation fields leaked into interaction request JSON: %s", raw)
	}
}

func TestInteractionRequestJSONIncludesPreviewAndResponseOmitsPIN(t *testing.T) {
	request := model.InteractionRequest{
		Kind:        model.InteractionKindConfirm,
		Message:     "Factory reset device-1?",
		Destructive: true,
		Preview: map[string]any{
			"deviceId": "device-1",
			"warnings": []string{"factory reset erases authenticator state"},
		},
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal interaction request: %v", err)
	}

	text := string(raw)
	if !strings.Contains(text, `"preview"`) || !strings.Contains(text, "factory reset erases authenticator state") {
		t.Fatalf("interaction request omitted preview: %s", text)
	}

	if strings.Contains(text, "pinUvAuthToken") {
		t.Fatalf("interaction request leaked token marker: %s", text)
	}

	if strings.Contains(text, "expectedPhrase") || strings.Contains(text, "typed-confirm") {
		t.Fatalf("interaction request included typed confirmation fields: %s", text)
	}

	if strings.Contains(text, "operationId") {
		t.Fatalf("operationId leaked into interaction request JSON: %s", text)
	}

	if strings.Contains(text, "sessionId") || strings.Contains(text, "interactionId") {
		t.Fatalf("runtime correlation fields leaked into interaction request JSON: %s", text)
	}

	response, err := json.Marshal(model.InteractionResponse{
		PIN: []byte("123456"),
	})
	if err != nil {
		t.Fatalf("marshal interaction response: %v", err)
	}

	if strings.Contains(string(response), "123456") || strings.Contains(string(response), "PIN") {
		t.Fatalf("interaction response leaked PIN: %s", response)
	}

	if strings.Contains(string(response), "phrase") {
		t.Fatalf("interaction response leaked phrase field: %s", response)
	}

	if strings.Contains(string(response), "operationId") {
		t.Fatalf("operationId leaked into interaction response JSON: %s", response)
	}

	if strings.Contains(string(response), "interactionId") || strings.Contains(string(response), `"kind"`) {
		t.Fatalf("runtime echo fields leaked into interaction response JSON: %s", response)
	}
}

func TestPublicDTOJSONContractsUseCTAP22Spellings(t *testing.T) {
	// This audit test keeps public input/output names aligned with CTAP 2.2 spellings.
	tests := []struct {
		name   string
		value  any
		want   []string
		reject []string
	}{
		{
			name: "inspect mirrors authenticator get info",
			value: model.InspectOutput{
				Result: model.NewInspectResult(report.DeviceReport{}, ctaptypes.AuthenticatorGetInfoResponse{
					ForcePINChange:              new(true),
					MinPINLength:                new(uint(4)),
					MaxCredentialIdLength:       new(uint(32)),
					MaxRPIDsForSetMinPINLength:  new(uint(3)),
					Algorithms:                  []webauthntypes.PublicKeyCredentialParameters{{Type: webauthntypes.PublicKeyCredentialTypePublicKey, Algorithm: key.Alg(-7)}},
					PinComplexityPolicy:         new(true),
					PinComplexityPolicyURL:      new("https://policy.example"),
					MaxPINLength:                new(uint(64)),
					EncCredStoreState:           new("encrypted-store-state"),
					AuthenticatorConfigCommands: []uint{1, 4},
					UvModality:                  new(ctaptypes.UserVerifyFingerprintInternal),
				}),
			},
			want: []string{
				`"result"`,
				`"forcePINChange":true`,
				`"minPINLength":4`,
				`"maxCredentialIdLength":32`,
				`"maxRPIDsForSetMinPINLength":3`,
				`"algorithms":[{"type":"public-key","alg":-7}]`,
				`"pinComplexityPolicyURL":"https://policy.example"`,
				`"maxPINLength":64`,
				`"encCredStoreState":"encrypted-store-state"`,
				`"authenticatorConfigCommands":[1,4]`,
				`"uvModality":2`,
				`"uvModalityLabel":"fingerprint_internal"`,
			},
			reject: []string{
				`"Result"`,
				`"forcePinChange"`,
				`"minPinLength"`,
				`"maxCredentialIDLength"`,
				`"maxRPIDsForSetMinPinLength"`,
				`"pinComplexityPolicyUrl"`,
				`"maxPinLength"`,
				`"Algorithm"`,
				`"Type"`,
			},
		},
		{
			name: "credential inventory uses WebAuthn acronym spellings",
			value: model.CredentialsOutput{
				Report: credentials.InventoryReport{
					Summary: credentials.InventorySummary{TotalRPs: 1},
					Groups: []credentials.CredentialGroup{
						{
							RPID:        "example.com",
							RPIDHashHex: "abcd",
							Credentials: []credentials.CredentialRecord{
								{
									CredentialIDHex:   "beef",
									UserIDHex:         "0102",
									LargeBlobKeyState: "available",
								},
							},
						},
					},
				},
			},
			want: []string{
				`"report"`,
				`"totalRPs":1`,
				`"rpID":"example.com"`,
				`"rpIDHashHex":"abcd"`,
				`"credentialIDHex":"beef"`,
				`"userIDHex":"0102"`,
				`"largeBlobKeyState":"available"`,
			},
			reject: []string{
				`"Report"`,
				`"totalRps"`,
				`"rpId"`,
				`"rpIdHashHex"`,
				`"credentialIdHex"`,
				`"userIdHex"`,
			},
		},
		{
			name: "credential mutation outputs use lower-case wrappers",
			value: model.CredentialDeleteOutput{
				Preview: credentials.DeletePreview{
					CredentialIDHex: "beef",
					RPID:            "example.com",
					UserIDHex:       "0102",
				},
				Result: &credentials.DeleteResult{
					DeviceID:        "device-1",
					CredentialIDHex: "beef",
					RPID:            "example.com",
					UserIDHex:       "0102",
				},
			},
			want: []string{
				`"preview"`,
				`"result"`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0102"`,
			},
			reject: []string{
				`"Preview"`,
				`"Result"`,
				`"credentialIdHex"`,
				`"rpId"`,
				`"userIdHex"`,
			},
		},
		{
			name: "credential update outputs preserve previous and current identities",
			value: model.CredentialUpdateOutput{
				Preview: credentials.UpdateUserPreview{
					CredentialIDHex: "beef",
					RPID:            "example.com",
					Current:         credentials.UserIdentity{UserIDHex: "0102"},
					Proposed:        credentials.UserIdentity{UserIDHex: "0304"},
				},
				Result: &credentials.UpdateUserResult{
					DeviceID:        "device-1",
					CredentialIDHex: "beef",
					RPID:            "example.com",
					Previous:        credentials.UserIdentity{UserIDHex: "0102"},
					Current:         credentials.UserIdentity{UserIDHex: "0304"},
				},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0304"`,
			},
			reject: []string{
				`"credentialIdHex"`,
				`"rpId"`,
				`"userIdHex"`,
			},
		},
		{
			name: "WebAuthn operation kinds and inputs use acronym spellings",
			value: model.MakeCredentialOperation{
				MakeCredentialInput: webauthn.MakeCredentialInput{
					RP:             webauthn.RelyingParty{ID: "example.com"},
					User:           webauthn.User{IDHex: "0102"},
					ClientDataJSON: []byte("client-data"),
					PubKeyCredParams: []webauthn.CredentialParameter{
						{Algorithm: -7},
					},
					ExcludeList: []webauthn.CredentialDescriptor{
						{IDHex: "beef"},
					},
				},
			},
			want: []string{
				`"rp"`,
				`"clientDataJSON"`,
				`"userIDHex":"0102"`,
				`"pubKeyCredParams"`,
				`"credentialIDHex":"beef"`,
			},
			reject: []string{
				`"clientDataJson"`,
				`"userIdHex"`,
				`"credentialIdHex"`,
			},
		},
		{
			name: "WebAuthn outputs include CTAP artifact spellings",
			value: model.MakeCredentialOutput{
				Result: &webauthn.MakeCredentialResult{
					DeviceID:                 "device-1",
					RPID:                     "example.com",
					Format:                   "packed",
					CredentialIDHex:          "beef",
					PublicKeyCOSEHex:         "a50102",
					AuthenticatorDataHex:     "0102",
					AttestationObjectCBORHex: "a30102",
				},
			},
			want: []string{
				`"rpID":"example.com"`,
				`"credentialIDHex":"beef"`,
				`"publicKeyCOSEHex":"a50102"`,
				`"authenticatorDataHex":"0102"`,
				`"attestationObjectCBORHex":"a30102"`,
			},
			reject: []string{
				`"rpId"`,
				`"credentialIdHex"`,
				`"publicKeyCoseHex"`,
				`"attestationObjectCborHex"`,
				`"pinUvAuthToken"`,
			},
		},
		{
			name: "config status uses CTAP get info spellings",
			value: model.ConfigStatusOutput{
				Report: config.StatusReport{
					PIN: config.PINStatus{
						State:               config.StateConfigured,
						Supported:           true,
						Configured:          new(true),
						MinPINLength:        new(uint(4)),
						MaxPINLength:        new(uint(64)),
						ForcePINChange:      new(true),
						PinComplexityURL:    new("https://policy.example"),
						PinComplexityPolicy: new(true),
						Retries: config.RetryState{
							State:           config.StateSupported,
							Remaining:       new(uint(5)),
							PowerCycleState: new(true),
						},
					},
					Bio: config.BioStatus{
						UVBioEnroll:     config.CapabilityState{Supported: true},
						UVModality:      new(uint(2)),
						UVModalityLabel: "fingerprint_internal",
					},
					AuthenticatorConfig: config.AuthenticatorConfigStatus{
						UVAcfg: config.CapabilityState{Supported: true},
					},
					Limits: config.LimitsStatus{
						MaxRPIDsForSetMinPINLength: new(uint(3)),
					},
				},
			},
			want: []string{
				`"report"`,
				`"minPINLength":4`,
				`"maxPINLength":64`,
				`"forcePINChange":true`,
				`"pinComplexityPolicyURL":"https://policy.example"`,
				`"uvBioEnroll"`,
				`"uvModality":2`,
				`"uvModalityLabel":"fingerprint_internal"`,
				`"uvAcfg"`,
				`"maxRPIDsForSetMinPINLength":3`,
				`"powerCycleState":true`,
			},
			reject: []string{
				`"Report"`,
				`"feature"`,
				`"uvBinding"`,
				`"modality"`,
				`"uvRequired"`,
				`"minPinLength"`,
				`"maxPinLength"`,
				`"forcePinChange"`,
				`"pinComplexityPolicyUrl"`,
				`"maxRpidsForSetMinPINLength"`,
				`"powerCycleRequired"`,
			},
		},
		{
			name: "bio sensor output uses spec-named string enums",
			value: model.BioSensorOutput{
				Report: config.BioSensorReport{
					Supported:                          true,
					Modality:                           new(config.BioModalityFingerprint),
					FingerprintKind:                    new(config.FingerprintKindTouch),
					MaxCaptureSamplesRequiredForEnroll: new(uint(4)),
					MaxTemplateFriendlyName:            new(uint(64)),
				},
			},
			want: []string{
				`"report"`,
				`"supported":true`,
				`"modality":"fingerprint"`,
				`"fingerprintKind":"touch"`,
				`"maxCaptureSamplesRequiredForEnroll":4`,
				`"maxTemplateFriendlyName":64`,
			},
			reject: []string{
				`"Report"`,
				`"modality":1`,
				`"fingerprintKind":1`,
				`"maxCaptureSamplesRequiredForEnrollment"`,
				`"maxTemplateFriendlyNameBytes"`,
			},
		},
		{
			name: "authenticator config output names set min PIN length result",
			value: model.AuthenticatorConfigOutput{
				Preview: config.AuthenticatorConfigPreview{
					Operation:             config.AuthenticatorConfigMinPINLength,
					CurrentMinPINLength:   new(uint(4)),
					RequestedMinPINLength: new(uint(8)),
					MaxPINLength:          new(uint(64)),
					RPIDs:                 []string{"example.com"},
					Authenticator: config.AuthenticatorConfigStatus{
						SetMinPINLength: config.CapabilityState{Supported: true},
					},
				},
				Result: &config.AuthenticatorConfigResult{
					Operation:       config.AuthenticatorConfigMinPINLength,
					NewMinPINLength: 8,
					State:           config.StateSupported,
				},
			},
			want: []string{
				`"operation":"setMinPINLength"`,
				`"currentMinPINLength":4`,
				`"requestedMinPINLength":8`,
				`"maxPINLength":64`,
				`"minPinLengthRPIDs":["example.com"]`,
				`"setMinPINLength"`,
				`"newMinPINLength":8`,
			},
			reject: []string{
				`"operation":"minPinLength"`,
				`"feature"`,
				`"currentMinPinLength"`,
				`"requestedMinPinLength"`,
				`"maxPinLength"`,
				`"rpIds"`,
				`"rpIDs"`,
				`"setMinPinLength"`,
				`"length"`,
			},
		},
		{
			name: "set min PIN length operation uses CTAP subcommand parameter names",
			value: model.SetMinPINLengthOperation{
				Length:              8,
				RPIDs:               []string{"example.com"},
				ForceChangePin:      true,
				PinComplexityPolicy: true,
			},
			want: []string{
				`"newMinPINLength":8`,
				`"minPinLengthRPIDs":["example.com"]`,
				`"forceChangePin":true`,
				`"pinComplexityPolicy":true`,
			},
			reject: []string{
				`"length"`,
				`"rpIds"`,
				`"rpIDs"`,
			},
		},
		{
			name: "set min PIN length request uses CTAP subcommand parameter names",
			value: config.MinPINLengthRequest{
				Length:              8,
				RPIDs:               []string{"example.com"},
				ForceChangePin:      true,
				PinComplexityPolicy: true,
			},
			want: []string{
				`"newMinPINLength":8`,
				`"minPinLengthRPIDs":["example.com"]`,
				`"forceChangePin":true`,
				`"pinComplexityPolicy":true`,
			},
			reject: []string{
				`"length"`,
				`"rpIds"`,
				`"rpIDs"`,
			},
		},
		{
			name: "bio outputs use template ID and enrollment sample names",
			value: model.BioEnrollOutput{
				Result: &config.BioEnrollResult{
					TemplateIDHex:          "abcd",
					LastEnrollSampleStatus: "good",
				},
			},
			want: []string{
				`"templateIDHex":"abcd"`,
				`"lastEnrollSampleStatus":"good"`,
			},
			reject: []string{
				`"templateIdHex"`,
				`"lastSampleStatus"`,
			},
		},
		{
			name: "bio list records use template ID spelling",
			value: model.BioListOutput{
				Report: config.BioListReport{
					Enrollments: []config.BioEnrollmentRecord{
						{TemplateIDHex: "abcd"},
					},
				},
			},
			want: []string{
				`"templateIDHex":"abcd"`,
			},
			reject: []string{
				`"templateIdHex"`,
			},
		},
		{
			name: "large blob read output uses credential target spellings",
			value: model.LargeBlobReadOutput{
				Report: largeblobs.ReadReport{
					LargeBlobKeyState: largeblobs.LargeBlobKeyAvailable,
					Target: largeblobs.BlobTarget{
						CredentialIDHex: "beef",
						RP:              credentials.RelyingParty{ID: "example.com", IDHashHex: "abcd"},
						User:            credentials.UserIdentity{UserIDHex: "0102"},
					},
				},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"idHashHex":"abcd"`,
				`"userIDHex":"0102"`,
			},
			reject: []string{
				`"credentialIdHex"`,
				`"userIdHex"`,
			},
		},
		{
			name: "large blob list output uses credential ID spelling",
			value: model.LargeBlobListOutput{
				Report: largeblobs.ListReport{
					Credentials: []largeblobs.ListCredential{
						{
							CredentialIDHex:   "beef",
							LargeBlobKeyState: largeblobs.LargeBlobKeyAvailable,
							User:              credentials.UserIdentity{UserIDHex: "0102"},
						},
					},
				},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"userIDHex":"0102"`,
			},
			reject: []string{
				`"credentialIdHex"`,
				`"userIdHex"`,
			},
		},
		{
			name: "large blob mutation output names serialized array size",
			value: model.LargeBlobMutationOutput{
				Preview: largeblobs.MutationPreview{
					Target:                             largeblobs.BlobTarget{CredentialIDHex: "beef"},
					LargeBlobKeyState:                  largeblobs.LargeBlobKeyAvailable,
					SerializedLargeBlobArraySizeBefore: 10,
					SerializedLargeBlobArraySizeAfter:  20,
				},
				Result: &largeblobs.MutationResult{
					CredentialIDHex:                    "beef",
					RPID:                               "example.com",
					UserIDHex:                          "0102",
					SerializedLargeBlobArraySizeBefore: 10,
					SerializedLargeBlobArraySizeAfter:  20,
				},
			},
			want: []string{
				`"serializedLargeBlobArraySizeBefore":10`,
				`"serializedLargeBlobArraySizeAfter":20`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0102"`,
				`"largeBlobKeyState":"available"`,
			},
			reject: []string{
				`"serializedArraySizeBefore"`,
				`"serializedArraySizeAfter"`,
				`"credentialIdHex"`,
				`"rpId"`,
				`"userIdHex"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("marshal output: %v", err)
			}

			text := string(raw)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Fatalf("JSON missing %s: %s", want, text)
				}
			}

			for _, reject := range tt.reject {
				if strings.Contains(text, reject) {
					t.Fatalf("JSON included obsolete %s: %s", reject, text)
				}
			}
		})
	}
}
