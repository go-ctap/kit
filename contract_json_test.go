package ctapkit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	rtinspect "github.com/go-ctap/kit/internal/inspect"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/operation"
	"github.com/go-ctap/kit/model/report"
	webauthn2 "github.com/go-ctap/kit/model/webauthn"
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
	if got := operation.MakeCredential; got != "webauthn.makeCredential" {
		t.Fatalf("MakeCredential kind = %q", got)
	}

	if got := operation.GetAssertion; got != "webauthn.getAssertion" {
		t.Fatalf("GetAssertion kind = %q", got)
	}
}

func TestUserVerificationInteractionJSON(t *testing.T) {
	modality := protocol.UserVerifyFingerprintInternal
	raw, err := json.Marshal(model.InteractionRequest{
		Kind:       model.InteractionKindUserVerification,
		Permission: "credentialManagement",
		UVModality: &modality,
	})
	if err != nil {
		t.Fatalf("marshal interaction request: %v", err)
	}

	if !strings.Contains(string(raw), `"kind":"user-verification"`) {
		t.Fatalf("user-verification JSON contract missing: %s", raw)
	}

	if !strings.Contains(string(raw), `"uvModality":2`) {
		t.Fatalf("user-verification modality missing: %s", raw)
	}

	flow, err := json.Marshal(VerificationFlowPIN)
	if err != nil {
		t.Fatalf("marshal verification flow: %v", err)
	}

	if string(flow) != `"pin"` {
		t.Fatalf("verification flow JSON = %s, want pin", flow)
	}

	if strings.Contains(string(raw), "operationId") {
		t.Fatalf("operationId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), "selectionId") {
		t.Fatalf("selectionId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), "interactionId") {
		t.Fatalf("interactionId leaked into interaction request JSON: %s", raw)
	}

	if strings.Contains(string(raw), `"status"`) {
		t.Fatalf("status leaked into interaction request JSON: %s", raw)
	}
}

func TestPINRetryInteractionJSON(t *testing.T) {
	retriesRemaining := uint(6)
	powerCycleState := false
	raw, err := json.Marshal(model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Permission: "credentialManagement",
		PINState: &model.PINInteractionState{
			Failure: failure.Snapshot(failure.New(
				failure.CodePINInvalid,
				failure.WithPhase(failure.PhaseTokenAcquisition),
			)),
			RetriesRemaining: &retriesRemaining,
			PowerCycleState:  &powerCycleState,
		},
	})
	if err != nil {
		t.Fatalf("marshal PIN retry interaction: %v", err)
	}

	want := `{"kind":"pin","permission":"credentialManagement","pinState":{"failure":{"code":"PIN_INVALID","category":"invalid-state","phase":"token-acquisition"},"retriesRemaining":6,"powerCycleState":false}}`
	if string(raw) != want {
		t.Fatalf("PIN retry interaction JSON = %s, want %s", raw, want)
	}
}

func TestInitialPINInteractionJSON(t *testing.T) {
	retriesRemaining := uint(7)
	powerCycleState := false
	raw, err := json.Marshal(model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Permission: "credentialManagement",
		PINState: &model.PINInteractionState{
			RetriesRemaining: &retriesRemaining,
			PowerCycleState:  &powerCycleState,
		},
	})
	if err != nil {
		t.Fatalf("marshal initial PIN interaction: %v", err)
	}

	want := `{"kind":"pin","permission":"credentialManagement","pinState":{"retriesRemaining":7,"powerCycleState":false}}`
	if string(raw) != want {
		t.Fatalf("initial PIN interaction JSON = %s, want %s", raw, want)
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

	if strings.Contains(string(raw), "selectionId") || strings.Contains(string(raw), "interactionId") {
		t.Fatalf("runtime correlation fields leaked into interaction request JSON: %s", raw)
	}
}

func TestInteractionRequestJSONIncludesPreviewAndResponseOmitsPIN(t *testing.T) {
	request := model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Factory reset fingerprint-1?",
		Destructive: true,
		Preview: map[string]any{
			"deviceFingerprint": "fingerprint-1",
			"warnings":          []string{"factory reset erases authenticator state"},
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

	if strings.Contains(text, "selectionId") || strings.Contains(text, "interactionId") {
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

func TestPublicDTOJSONContractsUseCTAP23Spellings(t *testing.T) {
	// This audit test keeps public input/output names aligned with CTAP 2.3 spellings.
	tests := []struct {
		name   string
		value  any
		want   []string
		reject []string
	}{
		{
			name: "inspect mirrors authenticator get info",
			value: rtinspect.BuildResult(report.DeviceReport{}, protocol.AuthenticatorGetInfoResponse{
				ForcePINChange:                true,
				MinPINLength:                  4,
				MaxCredentialIdLength:         32,
				MaxRPIDsForSetMinPINLength:    new(uint(3)),
				Algorithms:                    []credential.PublicKeyCredentialParameters{{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -7}},
				Transports:                    []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB},
				AttestationFormats:            []attestation.AttestationStatementFormatIdentifier{attestation.AttestationStatementFormatIdentifierPacked},
				VendorPrototypeConfigCommands: []protocol.VendorCommandID{0x1_0000_0000},
				PinComplexityPolicy:           new(true),
				PinComplexityPolicyURL:        []byte("https://policy.example"),
				MaxPINLength:                  64,
				EncCredStoreState:             []byte("encrypted-store-state"),
				AuthenticatorConfigCommands:   []protocol.ConfigSubCommand{1, 4},
				UvModality:                    new(protocol.UserVerifyFingerprintInternal),
			}),
			want: []string{
				`"forcePINChange":true`,
				`"minPINLength":4`,
				`"maxCredentialIdLength":32`,
				`"maxRPIDsForSetMinPINLength":3`,
				`"algorithms":[{"type":"public-key","alg":-7}]`,
				`"transports":["usb"]`,
				`"attestationFormats":["packed"]`,
				`"vendorPrototypeConfigCommands":[4294967296]`,
				`"pinComplexityPolicyURL":"aHR0cHM6Ly9wb2xpY3kuZXhhbXBsZQ=="`,
				`"maxPINLength":64`,
				`"encCredStoreState":"ZW5jcnlwdGVkLXN0b3JlLXN0YXRl"`,
				`"authenticatorConfigCommands":[1,4]`,
				`"uvModality":2`,
				`"uvModalityLabel":"fingerprint_internal"`,
				`"conformance"`,
			},
			reject: []string{
				`"result"`,
				`"Result"`,
				`"conformanceFindings"`,
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
			value: credentials.InventoryReport{
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
			want: []string{
				`"totalRPs":1`,
				`"rpID":"example.com"`,
				`"rpIDHashHex":"abcd"`,
				`"credentialIDHex":"beef"`,
				`"userIDHex":"0102"`,
				`"largeBlobKeyState":"available"`,
			},
			reject: []string{
				`"report"`,
				`"Report"`,
				`"totalRps"`,
				`"rpId"`,
				`"rpIdHashHex"`,
				`"credentialIdHex"`,
				`"userIdHex"`,
			},
		},
		{
			name: "credential operation inputs use ID spellings",
			value: credentials.UpdateUserOperation{
				Target:         credentials.CredentialTarget{},
				UserIDHex:      "0102",
				UserIDProvided: true,
			},
			want: []string{
				`"userIDHex":"0102"`,
				`"userIDProvided":true`,
			},
			reject: []string{
				`"userIdHex"`,
				`"userIdProvided"`,
			},
		},
		{
			name:  "credential delete input uses ID spelling",
			value: credentials.DeleteOperation{CredentialIDHex: "beef"},
			want:  []string{`"credentialIDHex":"beef"`},
			reject: []string{
				`"credentialIdHex"`,
			},
		},
		{
			name: "credential mutation outputs use lower-case wrappers",
			value: credentials.DeleteOutput{
				Preview: credentials.DeletePreview{
					CredentialIDHex: "beef",
					RPID:            "example.com",
					UserIDHex:       "0102",
				},
				Result: &credentials.DeleteResult{
					DeviceFingerprint: "fingerprint-1",
					CredentialIDHex:   "beef",
					RPID:              "example.com",
					UserIDHex:         "0102",
				},
			},
			want: []string{
				`"preview"`,
				`"result"`,
				`"deviceFingerprint":"fingerprint-1"`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0102"`,
			},
			reject: []string{
				`"Preview"`,
				`"Result"`,
				`"deviceId"`,
				`"credentialIdHex"`,
				`"rpId"`,
				`"userIdHex"`,
			},
		},
		{
			name: "credential update outputs preserve previous and current identities",
			value: credentials.UpdateUserOutput{
				Preview: credentials.UpdateUserPreview{
					CredentialIDHex: "beef",
					RPID:            "example.com",
					Current:         credentials.UserIdentity{UserIDHex: "0102"},
					Proposed:        credentials.UserIdentity{UserIDHex: "0304"},
				},
				Result: &credentials.UpdateUserResult{
					DeviceFingerprint: "fingerprint-1",
					CredentialIDHex:   "beef",
					RPID:              "example.com",
					Previous:          credentials.UserIdentity{UserIDHex: "0102"},
					Current:           credentials.UserIdentity{UserIDHex: "0304"},
				},
			},
			want: []string{
				`"deviceFingerprint":"fingerprint-1"`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0304"`,
			},
			reject: []string{
				`"deviceId"`,
				`"credentialIdHex"`,
				`"rpId"`,
				`"userIdHex"`,
			},
		},
		{
			name: "WebAuthn operation kinds and inputs use acronym spellings",
			value: webauthn2.MakeCredentialOperation{
				MakeCredentialInput: webauthn2.MakeCredentialInput{
					RP:             credential.PublicKeyCredentialRpEntity{ID: "example.com"},
					User:           credential.PublicKeyCredentialUserEntity{ID: []byte{0x01, 0x02}},
					ClientDataJSON: []byte("client-data"),
					PubKeyCredParams: []credential.PublicKeyCredentialParameters{
						{Algorithm: -7},
					},
					ExcludeList: []credential.PublicKeyCredentialDescriptor{
						{ID: []byte{0xbe, 0xef}},
					},
				},
			},
			want: []string{
				`"rp"`,
				`"clientDataJSON"`,
				`"id":"AQI="`,
				`"pubKeyCredParams"`,
				`"id":"vu8="`,
			},
			reject: []string{
				`"clientDataJson"`,
				`"userIdHex"`,
				`"userIDHex"`,
				`"credentialIdHex"`,
				`"credentialIDHex"`,
			},
		},
		{
			name: "WebAuthn outputs include CTAP artifact spellings",
			value: webauthn2.MakeCredentialOutput{
				Result: &webauthn2.MakeCredentialResult{
					DeviceFingerprint:        "fingerprint-1",
					RPID:                     "example.com",
					Format:                   "packed",
					CredentialIDHex:          "beef",
					PublicKeyCOSEHex:         "a50102",
					AuthenticatorDataHex:     "0102",
					AttestationObjectCBORHex: "a30102",
				},
			},
			want: []string{
				`"deviceFingerprint":"fingerprint-1"`,
				`"rpID":"example.com"`,
				`"credentialIDHex":"beef"`,
				`"publicKeyCOSEHex":"a50102"`,
				`"authenticatorDataHex":"0102"`,
				`"attestationObjectCBORHex":"a30102"`,
			},
			reject: []string{
				`"deviceId"`,
				`"rpId"`,
				`"credentialIdHex"`,
				`"publicKeyCoseHex"`,
				`"attestationObjectCborHex"`,
				`"pinUvAuthToken"`,
			},
		},
		{
			name: "config status uses CTAP get info spellings",
			value: config.StatusReport{
				PIN: config.PINStatus{
					State:               config.StateConfigured,
					Supported:           true,
					Configured:          new(true),
					MinPINLength:        4,
					MaxPINLength:        64,
					ForcePINChange:      true,
					PinComplexityURL:    "https://policy.example",
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
			want: []string{
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
				`"report"`,
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
			value: config.BioSensorReport{
				Supported:                          true,
				Modality:                           config.BioModalityFingerprint,
				FingerprintKind:                    config.FingerprintKindTouch,
				MaxCaptureSamplesRequiredForEnroll: new(uint(4)),
				MaxTemplateFriendlyName:            new(uint(64)),
			},
			want: []string{
				`"supported":true`,
				`"modality":"fingerprint"`,
				`"fingerprintKind":"touch"`,
				`"maxCaptureSamplesRequiredForEnroll":4`,
				`"maxTemplateFriendlyName":64`,
			},
			reject: []string{
				`"report"`,
				`"Report"`,
				`"modality":1`,
				`"fingerprintKind":1`,
				`"maxCaptureSamplesRequiredForEnrollment"`,
				`"maxTemplateFriendlyNameBytes"`,
			},
		},
		{
			name: "authenticator config output names set min PIN length result",
			value: config.AuthenticatorConfigOutput{
				Preview: config.AuthenticatorConfigPreview{
					Operation:           config.AuthenticatorConfigMinPINLength,
					CurrentMinPINLength: 4,
					NewMinPINLength:     new(uint(8)),
					MaxPINLength:        64,
					MinPINLengthRPIDs:   []string{"example.com"},
					Authenticator: config.AuthenticatorConfigStatus{
						SetMinPINLength: config.CapabilityState{Supported: true},
					},
				},
				Result: &config.AuthenticatorConfigResult{
					Operation:       config.AuthenticatorConfigMinPINLength,
					NewMinPINLength: new(uint(8)),
					State:           config.StateSupported,
				},
			},
			want: []string{
				`"operation":"setMinPINLength"`,
				`"currentMinPINLength":4`,
				`"newMinPINLength":8`,
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
			value: config.SetMinPINLengthOperation{
				NewMinPINLength:     new(uint(8)),
				MinPINLengthRPIDs:   []string{"example.com"},
				ForceChangePIN:      true,
				PINComplexityPolicy: true,
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
			name: "bio operation input uses template ID spelling",
			value: []any{
				config.BioRenameOperation{TemplateIDHex: "abcd"},
				config.BioRemoveOperation{TemplateIDHex: "dcba"},
			},
			want: []string{
				`"templateIDHex":"abcd"`,
				`"templateIDHex":"dcba"`,
			},
			reject: []string{
				`"templateIdHex"`,
			},
		},
		{
			name: "bio outputs use template ID and enrollment sample names",
			value: config.BioEnrollOutput{
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
			value: config.BioListReport{
				Enrollments: []config.BioEnrollmentRecord{
					{TemplateIDHex: "abcd"},
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
			value: largeblobs.ReadReport{
				LargeBlobKeyState: largeblobs.LargeBlobKeyAvailable,
				Target: largeblobs.BlobTarget{
					CredentialIDHex: "beef",
					RP:              credentials.RelyingParty{ID: "example.com", IDHashHex: "abcd"},
					User:            credentials.UserIdentity{UserIDHex: "0102"},
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
			name: "large blob operation input uses credential ID spelling",
			value: []any{
				largeblobs.ReadOperation{CredentialIDHex: "beef"},
				largeblobs.WriteOperation{CredentialIDHex: "cafe"},
				largeblobs.DeleteOperation{CredentialIDHex: "fade"},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"credentialIDHex":"cafe"`,
				`"credentialIDHex":"fade"`,
			},
			reject: []string{
				`"credentialIdHex"`,
			},
		},
		{
			name: "large blob list output uses credential ID spelling",
			value: largeblobs.ListReport{
				Credentials: []largeblobs.ListCredential{
					{
						CredentialIDHex:   "beef",
						LargeBlobKeyState: largeblobs.LargeBlobKeyAvailable,
						User:              credentials.UserIdentity{UserIDHex: "0102"},
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
			value: largeblobs.MutationOutput{
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

func TestDeviceReportVendorMetadataJSON(t *testing.T) {
	value := report.DeviceReport{
		Fingerprint: "attachment-1",
		Path:        "hid://one",
		Vendor:      report.VendorYubico,
		Metadata: &report.DeviceMetadata{
			Model:    "YubiKey 5C NFC",
			Serial:   "12345678",
			Firmware: "5.7.1",
			Interfaces: []report.InterfaceReport{{
				Interface: report.InterfaceUSB,
				Supported: []report.Capability{report.CapabilityU2F, report.CapabilityCTAP2},
				Enabled:   []report.Capability{report.CapabilityCTAP2},
			}},
		},
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	text := string(encoded)
	for _, want := range []string{
		`"fingerprint":"attachment-1"`,
		`"path":"hid://one"`,
		`"vendor":"yubico"`,
		`"metadata"`,
		`"model":"YubiKey 5C NFC"`,
		`"serial":"12345678"`,
		`"firmware":"5.7.1"`,
		`"interface":"usb"`,
		`"supported":["u2f","ctap2"]`,
		`"enabled":["ctap2"]`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON %s does not contain %s", text, want)
		}
	}

	for _, obsolete := range []string{`"deviceId"`, `"deviceFingerprint"`, `"stableId"`, `"location"`} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("JSON retained obsolete field %s: %s", obsolete, text)
		}
	}
}

func TestCTAP23JSONPresenceContracts(t *testing.T) {
	operation := config.SetMinPINLengthOperation{
		NewMinPINLength: new(uint(0)),
	}

	raw, err := json.Marshal(operation)
	if err != nil {
		t.Fatalf("Marshal operation: %v", err)
	}

	if string(raw) != `{"newMinPINLength":0}` {
		t.Fatalf("operation JSON = %s", raw)
	}

	absent, err := json.Marshal(config.SetMinPINLengthOperation{})
	if err != nil {
		t.Fatalf("Marshal absent operation: %v", err)
	}

	if string(absent) != "{}" {
		t.Fatalf("absent operation JSON = %s, want {}", absent)
	}

	emptyBlob := ""
	written := false
	thirdPartyPayment := false
	extensions := webauthn2.GetAssertionExtensionResults{
		Client: &webauthn2.GetAssertionClientExtensionResults{
			LargeBlob: &webauthn2.LargeBlobGetOutput{BlobHex: &emptyBlob, Written: &written},
		},
		Authenticator: &webauthn2.GetAssertionAuthenticatorExtensionOutputs{
			ThirdPartyPayment: &thirdPartyPayment,
		},
	}

	raw, err = json.Marshal(extensions)
	if err != nil {
		t.Fatalf("Marshal extensions: %v", err)
	}

	for _, want := range []string{`"blobHex":""`, `"written":false`, `"thirdPartyPayment":false`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("extensions JSON = %s, want %s", raw, want)
		}
	}

	storeState, err := json.Marshal(credentials.StoreStateResult{
		AuthenticatorIdentifierHex: "00",
		CredentialStoreStateHex:    "11",
	})
	if err != nil {
		t.Fatalf("Marshal store state: %v", err)
	}

	if !strings.Contains(string(storeState), `"authenticatorIdentifierHex":"00"`) ||
		!strings.Contains(string(storeState), `"credentialStoreStateHex":"11"`) {
		t.Fatalf("store state JSON = %s", storeState)
	}
}
