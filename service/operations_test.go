package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model"
)

func TestCredentialListRequestRefreshJSONContract(t *testing.T) {
	var legacy CredentialListRequest
	if err := json.Unmarshal([]byte(`{"sessionId":"session-1"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy credential list request: %v", err)
	}
	if legacy.SessionID != "session-1" || legacy.Refresh {
		t.Fatalf("legacy credential list request = %#v", legacy)
	}

	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy credential list request: %v", err)
	}
	if strings.Contains(string(raw), "refresh") {
		t.Fatalf("legacy credential list request included refresh: %s", raw)
	}

	refreshed := CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
		Refresh:          true,
	}
	raw, err = json.Marshal(refreshed)
	if err != nil {
		t.Fatalf("marshal refreshed credential list request: %v", err)
	}
	if !strings.Contains(string(raw), `"refresh":true`) {
		t.Fatalf("refreshed credential list request omitted refresh: %s", raw)
	}
}

func TestListCredentialsMapsRefreshToRuntimeOperation(t *testing.T) {
	runtime := &recordingOperationSession{}
	service := New()
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: runtime,
	}

	_, err := service.ListCredentials(context.Background(), CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
		Refresh:          true,
	})
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	operation, ok := runtime.operation.(model.ListCredentialsOperation)
	if !ok {
		t.Fatalf("runtime operation = %T, want ListCredentialsOperation", runtime.operation)
	}
	if !operation.Refresh {
		t.Fatal("runtime list credentials operation refresh = false, want true")
	}
}

func TestListCredentialsInvalidSessionReturnsTypedErrorEnvelope(t *testing.T) {
	service := New()

	envelope, err := service.ListCredentials(context.Background(), CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "missing-session"},
	})
	if err != nil {
		t.Fatalf("ListCredentials error = %v, want nil because the failure is in the envelope", err)
	}
	if envelope.SessionID != "missing-session" {
		t.Fatalf("envelope session ID = %q, want missing-session", envelope.SessionID)
	}
	if envelope.Kind != model.OperationListCredentials {
		t.Fatalf("envelope kind = %q, want %q", envelope.Kind, model.OperationListCredentials)
	}
	if envelope.Error == nil || envelope.Error.Category != model.ErrorInvalidSession {
		t.Fatalf("envelope error = %#v, want invalid-session", envelope.Error)
	}
}

func TestListCredentialsOperationFailureUsesOnlyTheTypedEnvelopeError(t *testing.T) {
	runtime := &recordingOperationSession{
		runErr: model.NewRuntimeError(model.ErrorCanceled, "operation canceled", context.Canceled),
	}
	service := New()
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: runtime,
	}

	envelope, err := service.ListCredentials(context.Background(), CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
	})
	if err != nil {
		t.Fatalf("ListCredentials error = %v, want nil because the failure is in the envelope", err)
	}
	if envelope.Error == nil || envelope.Error.Category != model.ErrorCanceled {
		t.Fatalf("envelope error = %#v, want canceled", envelope.Error)
	}
	if envelope.Result != nil {
		t.Fatalf("envelope result = %#v, want nil on operation failure", envelope.Result)
	}
}

func TestListCredentialsInternalTypeFailureDoesNotReturnAMeaningfulEnvelope(t *testing.T) {
	runtime := &recordingOperationSession{result: model.InspectOutput{}}
	service := New()
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: runtime,
	}

	envelope, err := service.ListCredentials(context.Background(), CredentialListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
	})
	if err == nil {
		t.Fatal("ListCredentials error = nil, want an internal type error")
	}
	if !strings.Contains(err.Error(), "returned model.InspectOutput") {
		t.Fatalf("ListCredentials error = %v, want typed result mismatch", err)
	}
	if envelope.OperationID != "" || envelope.SessionID != "" || envelope.Kind != "" || envelope.Error != nil || envelope.Result != nil {
		t.Fatalf("envelope = %#v, want zero envelope with internal error", envelope)
	}
}

func TestPINRequestsRoundTripSecrets(t *testing.T) {
	var setPIN PINSetRequest
	if err := json.Unmarshal([]byte(`{"sessionId":"session-1","newPIN":"123456","confirmed":true}`), &setPIN); err != nil {
		t.Fatalf("unmarshal set PIN request: %v", err)
	}
	if setPIN.SessionID != "session-1" || setPIN.NewPIN != "123456" || !setPIN.Confirmed {
		t.Fatalf("unexpected set PIN request: %#v", setPIN)
	}

	raw, err := json.Marshal(setPIN)
	if err != nil {
		t.Fatalf("marshal set PIN request: %v", err)
	}
	var setPINRoundTrip PINSetRequest
	if err := json.Unmarshal(raw, &setPINRoundTrip); err != nil {
		t.Fatalf("unmarshal marshaled set PIN request: %v", err)
	}
	if setPINRoundTrip != setPIN {
		t.Fatalf("set PIN request round trip = %#v, want %#v", setPINRoundTrip, setPIN)
	}

	var changePIN PINChangeRequest
	if err := json.Unmarshal([]byte(`{"sessionId":"session-1","currentPIN":"123456","newPIN":"654321","dryRun":true}`), &changePIN); err != nil {
		t.Fatalf("unmarshal change PIN request: %v", err)
	}
	if changePIN.SessionID != "session-1" || changePIN.CurrentPIN != "123456" || changePIN.NewPIN != "654321" || !changePIN.DryRun {
		t.Fatalf("unexpected change PIN request: %#v", changePIN)
	}

	raw, err = json.Marshal(changePIN)
	if err != nil {
		t.Fatalf("marshal change PIN request: %v", err)
	}
	var changePINRoundTrip PINChangeRequest
	if err := json.Unmarshal(raw, &changePINRoundTrip); err != nil {
		t.Fatalf("unmarshal marshaled change PIN request: %v", err)
	}
	if changePINRoundTrip != changePIN {
		t.Fatalf("change PIN request round trip = %#v, want %#v", changePINRoundTrip, changePIN)
	}
}

type recordingOperationSession struct {
	operation model.Operation
	result    model.OperationResult
	runErr    error
}

func (s *recordingOperationSession) Run(
	_ context.Context,
	operation model.Operation,
	_ model.InteractionHandler,
	_ ...ctapkit.RunOption,
) (model.OperationResult, error) {
	s.operation = operation
	if s.result != nil || s.runErr != nil {
		return s.result, s.runErr
	}

	return model.CredentialsOutput{}, nil
}

func (s *recordingOperationSession) Close() error { return nil }

func (s *recordingOperationSession) Info() model.SessionInfo { return model.SessionInfo{} }
