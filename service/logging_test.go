package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/largeblobs"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
)

func TestInvalidSessionOperationAppendsCompletedEntry(t *testing.T) {
	service := New()

	envelope, err := service.ListCredentials(context.Background(), CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "missing-session"},
	})
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	logs := serviceLogs(t, service)
	if len(logs) != 1 {
		t.Fatalf("log count = %d, want 1", len(logs))
	}
	entry := logs[0].Entry
	if entry.Outcome != model.LogOutcomeFailed || entry.Error == nil || entry.Error.Code != failure.CodeSessionInvalid {
		t.Fatalf("completed entry = %#v", logs[0])
	}
	if entry.OperationID != string(envelope.OperationID) || entry.SessionID != "missing-session" {
		t.Fatalf("log correlation = %#v, envelope operation ID = %q", entry, envelope.OperationID)
	}
	if entry.Response == nil || !json.Valid([]byte(entry.Response.JSON)) {
		t.Fatalf("response payload = %#v", entry.Response)
	}
}

func TestOperationLoggingRedactsPINAndConfirmation(t *testing.T) {
	const (
		currentPIN   = "sentinel-current-pin-1182"
		newPIN       = "sentinel-new-pin-9921"
		confirmation = "sentinel-reset-confirmation-5512"
	)
	service := New()
	service.sessions["session-1"] = &managedSession{
		id: "session-1",
		session: &recordingOperationSession{
			result: model.PINOutput{},
		},
	}

	_, err := service.ChangePIN(context.Background(), PINChangeRequest{
		OperationRequest:    OperationRequest{SessionID: "session-1"},
		CurrentPIN:          currentPIN,
		NewPIN:              newPIN,
		Confirmed:           true,
		ConfirmationMessage: confirmation,
	})
	if err != nil {
		t.Fatalf("ChangePIN: %v", err)
	}
	raw, err := json.Marshal(serviceLogs(t, service))
	if err != nil {
		t.Fatalf("Marshal logs: %v", err)
	}
	serialized := string(raw)
	for _, secret := range []string{currentPIN, newPIN, confirmation} {
		if strings.Contains(serialized, secret) || strings.Contains(serialized, base64.StdEncoding.EncodeToString([]byte(secret))) {
			t.Fatalf("logs contain %q: %s", secret, serialized)
		}
	}
	for _, field := range []string{"request.input.currentPIN", "request.input.newPIN", "request.input.confirmed", "request.input.confirmationMessage"} {
		if !strings.Contains(serialized, field) {
			t.Fatalf("logs do not record redacted field %q: %s", field, serialized)
		}
	}
}

func TestOperationLoggingDoesNotRequireEventEmitter(t *testing.T) {
	service := New()
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: &recordingOperationSession{result: model.CredentialsOutput{}},
	}

	envelope, err := service.ListCredentials(context.Background(), CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
	})
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if envelope.Error != nil || envelope.Result == nil {
		t.Fatalf("envelope = %#v", envelope)
	}
	if logs := serviceLogs(t, service); len(logs) == 0 {
		t.Fatal("operation journal is empty")
	}
}

func TestSessionLifecycleLoggingAppendsCompletedEntries(t *testing.T) {
	service := New()

	if _, err := service.OpenSession(context.Background(), OpenSessionRequest{Selector: "missing-device"}); err == nil {
		t.Fatal("OpenSession error = nil, want missing device failure")
	}
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: &recordingOperationSession{},
	}
	if _, err := service.CloseSession("session-1"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	logs := serviceLogs(t, service)
	if len(logs) != 2 {
		t.Fatalf("session lifecycle log count = %d, want 2: %#v", len(logs), logs)
	}
	if logs[0].Entry.Code != model.LogCodeSessionOpen || logs[0].Entry.Outcome != model.LogOutcomeFailed {
		t.Fatalf("open session entry = %#v", logs[0])
	}
	if logs[1].Entry.Code != model.LogCodeSessionClose || logs[1].Entry.Outcome != model.LogOutcomeSucceeded {
		t.Fatalf("close session entry = %#v", logs[1])
	}
}

func TestOperationLogEncoderNeverSerializesPrivateWebAuthnOrLargeBlobData(t *testing.T) {
	secrets := []string{
		"sentinel-credential-blob-9182",
		"sentinel-hmac-salt-1827",
		"sentinel-prf-input-8271",
		"sentinel-hmac-output-7711",
		"sentinel-prf-output-6612",
		"sentinel-large-blob-payload-5004",
		"sentinel-large-blob-decoded-2910",
		"sentinel-credential-blob-output-2801",
	}
	makeInput := appwebauthn.MakeCredentialInput{Extensions: &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateCredentialBlobInputs: &ctapwebauthn.CreateCredentialBlobInputs{CredBlob: []byte(secrets[0])},
		CreateHMACSecretMCInputs: &ctapwebauthn.CreateHMACSecretMCInputs{HMACGetSecret: ctapwebauthn.HMACGetSecretInput{
			Salt1: []byte(secrets[1]),
		}},
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte(secrets[2])},
		}},
		CreateHMACSecretInputs: &ctapwebauthn.CreateHMACSecretInputs{HMACCreateSecret: true},
	}}
	request := operationRequestLogValue(OperationRequest{SessionID: "session-1"}, model.MakeCredentialOperation{
		MakeCredentialInput: makeInput,
	})
	makeOutput := model.MakeCredentialOutput{
		Preview: appwebauthn.MakeCredentialPreview{Input: makeInput},
		Result: &appwebauthn.MakeCredentialResult{
			AuthenticatorDataHex:     secrets[3],
			AttestationObjectCBORHex: secrets[4],
			ExtensionResults: &appwebauthn.MakeCredentialExtensionResults{
				Client: &appwebauthn.MakeCredentialClientExtensionResults{
					HMACSecretMC: &appwebauthn.HMACSecretOutput{Output1Hex: secrets[3]},
					PRF: &appwebauthn.MakeCredentialPRFOutput{
						Enabled: true,
						Results: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte(secrets[4])},
					},
				},
			}},
	}
	response := operationEnvelopeLogValue(operationEnvelope{Result: makeOutput})
	getInput := appwebauthn.GetAssertionInput{Extensions: &ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		GetHMACSecretInputs: &ctapwebauthn.GetHMACSecretInputs{HMACGetSecret: ctapwebauthn.HMACGetSecretInput{
			Salt1: []byte(secrets[1]),
		}},
		PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
			Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte(secrets[2])},
		}},
	}}
	getRequest := operationRequestLogValue(OperationRequest{SessionID: "session-1"}, model.GetAssertionOperation{
		GetAssertionInput: getInput,
	})
	getResponse := operationEnvelopeLogValue(operationEnvelope{Result: model.GetAssertionOutput{
		Preview: appwebauthn.GetAssertionPreview{Input: getInput},
		Result: &appwebauthn.GetAssertionResult{Assertions: []appwebauthn.Assertion{{
			AuthenticatorDataHex: secrets[3],
			ExtensionResults: &appwebauthn.GetAssertionExtensionResults{
				Client: &appwebauthn.GetAssertionClientExtensionResults{
					CredentialBlob: &appwebauthn.CredentialBlobGetOutput{ValueHex: secrets[7]},
					HMACSecret:     &appwebauthn.HMACSecretOutput{Output1Hex: secrets[3]},
					PRF: &appwebauthn.GetAssertionPRFOutput{
						Results: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte(secrets[4])},
					},
				},
			},
		}},
		}}})

	largeBlobRequest := operationRequestLogValue(OperationRequest{SessionID: "session-1"}, model.WriteLargeBlobOperation{
		Payload: []byte(secrets[5]),
	})
	largeBlobResponse := operationEnvelopeLogValue(operationEnvelope{Result: model.LargeBlobReadOutput{
		Report: largeblobs.ReadReport{
			RawHex:       secrets[5],
			RawByteCount: len(secrets[5]),
			Decode: largeblobs.DecodeStatus{
				Success:      true,
				DecodedText:  secrets[6],
				DecodedValue: map[string]string{"private": secrets[6]},
			},
		},
	}})

	entries := []model.LogEntry{
		{
			Request:        kitlog.Payload(request),
			Response:       kitlog.Payload(response),
			RedactedFields: slices.Concat(request.RedactedFields, response.RedactedFields),
		},
		{
			Request:        kitlog.Payload(getRequest),
			Response:       kitlog.Payload(getResponse),
			RedactedFields: slices.Concat(getRequest.RedactedFields, getResponse.RedactedFields),
		},
		{
			Request:        kitlog.Payload(largeBlobRequest),
			Response:       kitlog.Payload(largeBlobResponse),
			RedactedFields: slices.Concat(largeBlobRequest.RedactedFields, largeBlobResponse.RedactedFields),
		},
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("Marshal envelopes: %v", err)
	}
	serialized := string(raw)
	for _, secret := range secrets {
		if strings.Contains(serialized, secret) || strings.Contains(serialized, base64.StdEncoding.EncodeToString([]byte(secret))) {
			t.Fatalf("log envelopes contain private value %q: %s", secret, serialized)
		}
	}
	for _, field := range []string{
		"request.input.extensions.credBlob",
		"request.input.extensions.hmacGetSecret",
		"request.input.extensions.prf",
		"response.result.result.authenticatorDataHex",
		"response.result.result.attestationObjectCBORHex",
		"response.result.result.extensionResults.client.hmac-secret-mc",
		"response.result.result.extensionResults.client.prf",
		"response.result.result.assertions.0.authenticatorDataHex",
		"response.result.result.assertions.0.extensionResults.client.getCredBlob.valueHex",
		"request.input.payload",
		"response.result.report.rawHex",
		"response.result.report.decode.decodedText",
		"response.result.report.decode.decodedValue",
	} {
		if !strings.Contains(serialized, field) {
			t.Fatalf("log envelopes do not record redacted field %q: %s", field, serialized)
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func TestProgressLoggingDoesNotDuplicateOperationEvent(t *testing.T) {
	emitter := newCountingLogEmitter()
	service := New(WithEventEmitter(emitter))
	service.sessions["session-1"] = &managedSession{id: "session-1"}
	service.operations["operation-1"] = &operationState{
		id:        "operation-1",
		sessionID: "session-1",
		kind:      model.OperationListCredentials,
	}

	sessionEventSink{service: service, sessionID: "session-1"}.Emit(model.OperationEvent{
		Stage: model.OperationStageEnumeratingCredentials,
	})
	if got := emitter.count(EventOperationEvent); got != 1 {
		t.Fatalf("operation event count = %d, want 1", got)
	}
	logs := serviceLogs(t, service)
	if len(logs) != 1 || logs[0].Entry.Code != model.LogCodeOperationProgress {
		t.Fatalf("progress logs = %#v", logs)
	}
	if logs[0].Entry.SessionID != "session-1" || logs[0].Entry.OperationID != "operation-1" {
		t.Fatalf("progress correlation = %#v", logs[0])
	}
}

func TestInteractionLoggingAppendsCompletedEntriesWithoutDuplicatePrompt(t *testing.T) {
	const sentinelPIN = "sentinel-interaction-pin-8301"
	emitter := newCountingLogEmitter()
	service := New(WithEventEmitter(emitter))
	service.operations["operation-1"] = &operationState{
		id:        "operation-1",
		sessionID: "session-1",
		kind:      model.OperationListCredentials,
		done:      make(chan struct{}),
	}
	handler := interactionHandler{
		service:     service,
		sessionID:   "session-1",
		operationID: "operation-1",
		kind:        model.OperationListCredentials,
	}

	result := make(chan error, 1)
	go func() {
		_, err := handler.RequestInteraction(model.InteractionRequest{})
		result <- err
	}()
	prompt := <-emitter.prompts
	resolved, err := service.ResolveInteraction(context.Background(), InteractionAnswer{
		InteractionID: prompt.InteractionID,
		PIN:           sentinelPIN,
	})
	if err != nil || !resolved {
		t.Fatalf("ResolveInteraction = %v, %v", resolved, err)
	}
	if err := <-result; err != nil {
		t.Fatalf("RequestInteraction: %v", err)
	}
	if got := emitter.count(EventInteractionRequested); got != 1 {
		t.Fatalf("interaction event count = %d, want 1", got)
	}
	logs := serviceLogs(t, service)
	if len(logs) != 2 {
		t.Fatalf("interaction log count = %d, want 2: %#v", len(logs), logs)
	}
	for _, record := range logs {
		if record.Entry.SessionID != "session-1" || record.Entry.OperationID != "operation-1" {
			t.Fatalf("interaction correlation = %#v", record.Entry)
		}
	}
	raw, err := json.Marshal(logs)
	if err != nil {
		t.Fatalf("Marshal logs: %v", err)
	}
	if strings.Contains(string(raw), sentinelPIN) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(sentinelPIN))) {
		t.Fatalf("interaction logs contain PIN: %s", raw)
	}
}

func TestInteractionLogEncoderKeepsPreviewAndRedactsMessage(t *testing.T) {
	const secretMessage = "reset phrase sentinel"
	value := interactionRequestLogValue(model.InteractionRequest{
		Kind:        model.InteractionKindConfirm,
		Message:     secretMessage,
		Permission:  "authenticatorConfiguration",
		Destructive: true,
		Preview: map[string]any{
			"publicDiagnostic": "kept",
		},
	})
	payload := kitlog.Payload(value)
	if payload == nil {
		t.Fatal("payload is nil")
	}
	if strings.Contains(payload.JSON, secretMessage) {
		t.Fatalf("payload contains interaction message: %s", payload.JSON)
	}
	var decoded struct {
		Preview map[string]any `json:"preview"`
	}
	if err := json.Unmarshal([]byte(payload.JSON), &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.Preview["publicDiagnostic"] != "kept" {
		t.Fatalf("payload omitted preview: %s", payload.JSON)
	}
	if !slices.Contains(value.RedactedFields, "request.message") {
		t.Fatalf("redacted fields = %v", value.RedactedFields)
	}
}

type countingLogEmitter struct {
	mu      sync.Mutex
	names   []string
	prompts chan InteractionPrompt
}

func newCountingLogEmitter() *countingLogEmitter {
	return &countingLogEmitter{prompts: make(chan InteractionPrompt, 1)}
}

func (e *countingLogEmitter) Emit(name string, payload any) {
	e.mu.Lock()
	e.names = append(e.names, name)
	e.mu.Unlock()
	if prompt, ok := payload.(InteractionPrompt); ok {
		e.prompts <- prompt
	}
}

func (e *countingLogEmitter) count(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := 0
	for _, candidate := range e.names {
		if candidate == name {
			count++
		}
	}
	return count
}

func serviceLogs(t *testing.T, service *Service) []model.LogJournalRecord {
	t.Helper()
	return service.ReadLogs(ReadLogsRequest{}).Entries
}
