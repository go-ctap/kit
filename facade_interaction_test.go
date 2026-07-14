package ctapkit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
)

func TestTypedOperationDoesNotMarshalSecrets(t *testing.T) {
	req := model.ChangePINOperation{
		CurrentPIN: "1234",
		NewPIN:     "5678",
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if string(raw) != `{}` {
		t.Fatalf("marshaled operation = %s", raw)
	}
}

func TestPINInteractionRejectsEmptyPINAtSessionRun(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		return model.InteractionResponse{}, nil
	})

	_, err := session.Run(context.Background(), model.WriteLargeBlobOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		Confirmed:       true,
	}, handler)
	requireFailureCode(t, err, failure.CodePINRequired)

	if got := a.pinCalls.Load(); got != 0 {
		t.Fatalf("PIN token calls = %d, want 0", got)
	}
}

func TestPINInteractionWithoutHandlerReturnsInvalidState(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.WriteLargeBlobOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		Confirmed:       true,
	}, nil)
	requireFailureCode(t, err, failure.CodeInteractionHandlerRequired)

	if !hasStage(events.Events(), model.OperationStageInteractionRequired) {
		t.Fatal("interaction-required was not emitted before missing handler error")
	}

	if got := a.pinCalls.Load(); got != 0 {
		t.Fatalf("PIN token calls = %d, want 0", got)
	}
}

func TestCanceledContextDuringInteractionReturnsCanceledFailure(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		cancel()

		return model.InteractionResponse{}, context.Canceled
	})

	_, err := session.Run(ctx, model.WriteLargeBlobOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		Confirmed:       true,
	}, handler)
	requireFailureCode(t, err, failure.CodeOperationCanceled)

	if got := a.pinCalls.Load(); got != 0 {
		t.Fatalf("PIN token calls = %d, want 0", got)
	}
}

func TestConfirmInteractionCanceledReturnsCanceledFailure(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinMutationCountingAuthenticator{}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindConfirm {
			t.Fatalf("interaction kind = %s, want confirm", req.Kind)
		}

		return model.InteractionResponse{Canceled: true}, nil
	})

	_, err := session.Run(context.Background(), model.SetPINOperation{
		NewPIN: "1234",
	}, handler)
	requireFailureCode(t, err, failure.CodeInteractionCanceled)

	if got := a.setCalls.Load(); got != 0 {
		t.Fatalf("SetPIN calls = %d, want 0", got)
	}

}

func TestResetConfirmInteractionCanceledReturnsCanceledFailure(t *testing.T) {
	events := &recordingEventSink{}
	a := &resetCountingAuthenticator{}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindConfirm {
			t.Fatalf("interaction kind = %s, want confirm", req.Kind)
		}
		if !req.Destructive {
			t.Fatal("reset confirm interaction destructive = false, want true")
		}

		return model.InteractionResponse{Canceled: true}, nil
	})

	_, err := session.Run(context.Background(), model.ResetFactoryOperation{}, handler)
	requireFailureCode(t, err, failure.CodeInteractionCanceled)

	if got := a.resetCount.Load(); got != 0 {
		t.Fatalf("Reset count = %d, want 0", got)
	}

	for _, event := range events.Events() {
		if event.Kind == model.InteractionKindTouch {
			t.Fatal("touch interaction emitted for canceled confirm")
		}
	}

}

func TestPINInteractionHandlerReceivesRequestAndValidPINContinues(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	var (
		requests     []model.InteractionRequest
		returnedPINs [][]byte
	)

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		requests = append(requests, req)
		pin := []byte("1234")
		returnedPINs = append(returnedPINs, pin)

		return model.InteractionResponse{
			PIN: pin,
		}, nil
	})

	result, err := session.Run(context.Background(), model.WriteLargeBlobOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		Confirmed:       true,
	}, handler)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if _, ok := result.(model.LargeBlobMutationOutput); !ok {
		t.Fatalf("result = %#v, want large blob mutation output", result)
	}

	if len(requests) != 2 {
		t.Fatalf("PIN requests = %d, want 2", len(requests))
	}

	for _, pin := range returnedPINs {
		if !bytes.Equal(pin, []byte{0, 0, 0, 0}) {
			t.Fatalf("handler-owned PIN was not wiped: %#v", pin)
		}
	}

	for _, req := range requests {
		if req.Kind != model.InteractionKindPIN {
			t.Fatalf("unexpected PIN request: %#v", req)
		}
	}

	if got := a.pinCalls.Load(); got != 2 {
		t.Fatalf("PIN token calls = %d, want 2", got)
	}
}
