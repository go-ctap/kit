package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
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

func TestLargeBlobListRequestRefreshJSONContract(t *testing.T) {
	var legacy LargeBlobListRequest
	if err := json.Unmarshal([]byte(`{"sessionId":"session-1"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy large blob list request: %v", err)
	}
	if legacy.SessionID != "session-1" || legacy.Refresh {
		t.Fatalf("legacy large blob list request = %#v", legacy)
	}

	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy large blob list request: %v", err)
	}
	if strings.Contains(string(raw), "refresh") {
		t.Fatalf("legacy large blob list request included refresh: %s", raw)
	}

	refreshed := LargeBlobListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
		Refresh:          true,
	}
	raw, err = json.Marshal(refreshed)
	if err != nil {
		t.Fatalf("marshal refreshed large blob list request: %v", err)
	}
	if !strings.Contains(string(raw), `"refresh":true`) {
		t.Fatalf("refreshed large blob list request omitted refresh: %s", raw)
	}
}

func TestListLargeBlobsMapsRefreshToRuntimeOperation(t *testing.T) {
	runtime := &recordingOperationSession{result: model.LargeBlobListOutput{}}
	service := New()
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: runtime,
	}

	_, err := service.ListLargeBlobs(context.Background(), LargeBlobListRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
		Refresh:          true,
	})
	if err != nil {
		t.Fatalf("ListLargeBlobs: %v", err)
	}

	operation, ok := runtime.operation.(model.ListLargeBlobsOperation)
	if !ok {
		t.Fatalf("runtime operation = %T, want ListLargeBlobsOperation", runtime.operation)
	}
	if !operation.Refresh {
		t.Fatal("runtime list large blobs operation refresh = false, want true")
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
	if envelope.Error == nil || envelope.Error.Code != failure.CodeSessionInvalid {
		t.Fatalf("envelope error = %#v, want %s", envelope.Error, failure.CodeSessionInvalid)
	}
	if envelope.Error.Category != failure.CategoryInvalidSession || envelope.Error.Phase != failure.PhaseSession {
		t.Fatalf("envelope error = %#v, want invalid-session/session", envelope.Error)
	}
}

func TestListCredentialsOperationFailureUsesOnlyTheTypedEnvelopeError(t *testing.T) {
	runtime := &recordingOperationSession{
		runErr: failure.Wrap(
			failure.CodeOperationCanceled,
			context.Canceled,
			failure.WithPhase(failure.PhaseAuthenticatorCommand),
		),
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
	if envelope.Error == nil || envelope.Error.Code != failure.CodeOperationCanceled {
		t.Fatalf("envelope error = %#v, want %s", envelope.Error, failure.CodeOperationCanceled)
	}
	if envelope.Error.Category != failure.CategoryCanceled {
		t.Fatalf("envelope error category = %q, want %q", envelope.Error.Category, failure.CategoryCanceled)
	}
	if envelope.Result != nil {
		t.Fatalf("envelope result = %#v, want nil on operation failure", envelope.Result)
	}
	if envelope.SessionClosed {
		t.Fatal("envelope sessionClosed = true, want false")
	}
	if _, err := service.Session("session-1"); err != nil {
		t.Fatalf("Session: %v", err)
	}
}

func TestOperationEnvelopeReportsAndRetiresClosedSession(t *testing.T) {
	runtime := &recordingOperationSession{
		info: model.SessionInfo{Closed: true},
		runErr: failure.Wrap(
			failure.CodeOperationCanceled,
			context.Canceled,
			failure.WithPhase(failure.PhaseAuthenticatorCommand),
		),
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
		t.Fatalf("ListCredentials: %v", err)
	}
	if !envelope.SessionClosed {
		t.Fatal("envelope sessionClosed = false, want true")
	}
	if envelope.Error == nil || envelope.Error.Code != failure.CodeOperationCanceled {
		t.Fatalf("envelope error = %#v, want %s", envelope.Error, failure.CodeOperationCanceled)
	}

	if _, err := service.Session("session-1"); !failure.IsCode(err, failure.CodeSessionInvalid) {
		t.Fatalf("Session error = %v, want %s", err, failure.CodeSessionInvalid)
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
	info      model.SessionInfo
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

func (s *recordingOperationSession) Info() model.SessionInfo { return s.info }
