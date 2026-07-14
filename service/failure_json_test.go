package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
)

func TestGetAssertionFailureEnvelopeExactJSON(t *testing.T) {
	err := failure.Wrap(
		failure.CodeAssertionNotAllowed,
		errors.New("authenticator rejected the CTAP operation in its current state"),
		failure.WithOperation(string(model.OperationGetAssertion)),
		failure.WithPhase(failure.PhaseAuthenticatorCommand),
		failure.WithCTAP(&failure.CTAPDetail{
			Command:     "authenticatorGetAssertion",
			CommandCode: 2,
			Status:      "CTAP2_ERR_NOT_ALLOWED",
			StatusCode:  48,
		}),
	)
	envelope := GetAssertionEnvelope{
		OperationEnvelopeMeta: OperationEnvelopeMeta{
			OperationID: "operation-1",
			SessionID:   "session-1",
			Kind:        model.OperationGetAssertion,
			Error:       failure.Snapshot(err),
		},
	}

	raw, marshalErr := json.Marshal(envelope)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}

	want := `{"operationId":"operation-1","sessionId":"session-1","kind":"webauthn.getAssertion","error":{"code":"ASSERTION_NOT_ALLOWED","category":"invalid-state","operation":"webauthn.getAssertion","phase":"authenticator-command","ctap":{"command":"authenticatorGetAssertion","commandCode":2,"status":"CTAP2_ERR_NOT_ALLOWED","statusCode":48}}}`
	if string(raw) != want {
		t.Fatalf("JSON = %s, want %s", raw, want)
	}
}

func TestDirectServiceErrorIsTypedAndMachineReadable(t *testing.T) {
	service := New()

	_, err := service.Session(t.Context(), "missing-session")
	if err == nil {
		t.Fatal("Session error = nil, want failure")
	}

	var typed *failure.Error
	if !errors.As(err, &typed) {
		t.Fatalf("Session error type = %T, want *failure.Error", err)
	}
	if !failure.IsCode(err, failure.CodeSessionInvalid) {
		t.Fatalf("Session error = %v, want %s", err, failure.CodeSessionInvalid)
	}
}

func TestDirectServiceContextErrorsHaveDistinctCodes(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	deadline, deadlineCancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer deadlineCancel()

	tests := []struct {
		name string
		ctx  context.Context
		code failure.Code
	}{
		{name: "canceled", ctx: canceled, code: failure.CodeOperationCanceled},
		{name: "deadline", ctx: deadline, code: failure.CodeOperationTimeout},
	}

	service := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Sessions(tt.ctx)
			if !failure.IsCode(err, tt.code) {
				t.Fatalf("Sessions error = %v, want %s", err, tt.code)
			}
			snapshot := failure.Snapshot(err)
			if snapshot.Phase != failure.PhaseSession {
				t.Fatalf("Sessions phase = %q, want %q", snapshot.Phase, failure.PhaseSession)
			}
		})
	}
}

func TestBioEnrollEnvelopeKeepsPartialResultWithFailure(t *testing.T) {
	runtime := &recordingOperationSession{
		result: model.BioEnrollOutput{Result: &config.BioEnrollResult{
			TemplateIDHex:   "aabb",
			CancelAttempted: true,
		}},
		runErr: failure.Wrap(
			failure.CodeBioInteractionTimeout,
			errors.New("capture timeout after touching sensor"),
			failure.WithOperation(string(model.OperationBioEnroll)),
			failure.WithPhase(failure.PhaseInteraction),
		),
	}
	service := New()
	service.sessions["session-1"] = &managedSession{
		id:      "session-1",
		session: runtime,
	}

	envelope, err := service.BioEnroll(t.Context(), BioEnrollRequest{
		OperationRequest: OperationRequest{SessionID: "session-1"},
	})
	if err != nil {
		t.Fatalf("BioEnroll: %v", err)
	}
	if envelope.Error == nil || envelope.Error.Code != failure.CodeBioInteractionTimeout {
		t.Fatalf("error = %#v, want %s", envelope.Error, failure.CodeBioInteractionTimeout)
	}
	if envelope.Result == nil || envelope.Result.Result == nil || envelope.Result.Result.TemplateIDHex != "aabb" {
		t.Fatalf("partial result = %#v, want template aabb", envelope.Result)
	}
}
