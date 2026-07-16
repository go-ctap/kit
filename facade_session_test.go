package ctapkit

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
)

func TestSessionTypedOperationContract(t *testing.T) {
	session := openContractSession(t, nil, nil)
	defer func() { _ = session.Close() }()

	output, err := session.Run(context.Background(), model.ConfigStatusOperation{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	typed, ok := output.(model.ConfigStatusOutput)
	if !ok || typed.Report.Device.Fingerprint == "" {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestSessionPreCompletedContextHasSessionPhase(t *testing.T) {
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

	session := openContractSession(t, nil, nil)
	defer func() { _ = session.Close() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := session.Run(tt.ctx, model.ConfigStatusOperation{}, nil)
			requireFailureCode(t, err, tt.code)

			snapshot := failure.Snapshot(err)
			if snapshot.Operation != string(model.OperationConfigStatus) {
				t.Fatalf("operation = %q, want %q", snapshot.Operation, model.OperationConfigStatus)
			}
			if snapshot.Phase != failure.PhaseSession {
				t.Fatalf("phase = %q, want %q", snapshot.Phase, failure.PhaseSession)
			}
		})
	}
}

func TestSessionCloseClosesAuthenticatorOnce(t *testing.T) {
	a := &closeCountingAuthenticator{
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)

	go func() {
		firstErr <- session.Close()
	}()

	<-a.closeStarted

	go func() {
		secondErr <- session.Close()
	}()

	close(a.releaseClose)

	for _, err := range []error{<-firstErr, <-secondErr} {
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestSessionCloseCancelsActiveRunAndClosesAuthenticatorOnce(t *testing.T) {
	events := &recordingEventSink{}
	a := &cancelablePINAuthenticator{
		pinOnlyLargeBlobWriteEventAuthenticator: pinOnlyLargeBlobWriteEventAuthenticator{
			largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
		},
		closeStarted: make(chan struct{}),
	}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})

	interactionEntered := make(chan struct{})
	runDone := make(chan error, 1)
	handler := interactionHandlerFunc(func(_ model.InteractionRequest) (model.InteractionResponse, error) {
		close(interactionEntered)

		select {}
	})

	go func() {
		_, err := session.Run(context.Background(), model.WriteLargeBlobOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("test"),
			Confirmed:       true,
		}, handler)
		runDone <- err
	}()

	select {
	case <-interactionEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach PIN interaction")
	}

	closeDone := make(chan error, 2)

	go func() { closeDone <- session.Close() }()

	select {
	case <-a.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Session.Close did not close authenticator")
	}

	go func() { closeDone <- session.Close() }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Session.Close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Session.Close did not return")
		}
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("Run was not canceled by Session.Close")
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestSessionCloseDoesNotWaitForStuckInteractionHandler(t *testing.T) {
	events := &recordingEventSink{}
	a := &cancelablePINAuthenticator{
		pinOnlyLargeBlobWriteEventAuthenticator: pinOnlyLargeBlobWriteEventAuthenticator{
			largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
		},
		closeStarted: make(chan struct{}),
	}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})

	interactionEntered := make(chan struct{})
	unblockHandler := make(chan struct{})
	runDone := make(chan error, 1)
	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		close(interactionEntered)
		<-unblockHandler

		return model.InteractionResponse{
			PIN: []byte("1234"),
		}, nil
	})

	go func() {
		_, err := session.Run(context.Background(), model.WriteLargeBlobOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("test"),
			Confirmed:       true,
		}, handler)
		runDone <- err
	}()

	select {
	case <-interactionEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach PIN interaction")
	}

	closeDone := make(chan error, 1)

	go func() { closeDone <- session.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Session.Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Session.Close waited for stuck interaction handler")
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("Run was not canceled by Session.Close")
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}

	close(unblockHandler)
}

func TestSessionCloseCancelsBlockedAuthenticatorCommand(t *testing.T) {
	a := &blockingConfigAuthenticator{commandEntered: make(chan struct{})}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	runDone := make(chan error, 1)
	go func() {
		_, err := session.Run(
			context.Background(),
			model.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable, Confirmed: true},
			userVerificationHandler(t),
		)
		runDone <- err
	}()

	select {
	case <-a.commandEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach authenticator command")
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Session.Close: %v", err)
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("blocked authenticator command did not observe cancellation")
	}
}

func TestRunAfterSessionCloseIsRejected(t *testing.T) {
	session := openContractSession(t, nil, nil)

	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := session.Run(context.Background(), model.ConfigStatusOperation{}, nil)
	requireFailureCode(t, err, failure.CodeSessionClosed)

	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
}

func TestTransportConnectionFailureClosesSession(t *testing.T) {
	tests := []ctaptransport.IOOperation{
		ctaptransport.IORead,
		ctaptransport.IOWrite,
		ctaptransport.IOTransmit,
	}

	for _, operation := range tests {
		t.Run(string(operation), func(t *testing.T) {
			a := &transportFailureAuthenticator{operation: operation}
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})

			_, err := session.Run(context.Background(), model.SetPINOperation{
				NewPIN:    "1234",
				Confirmed: true,
			}, nil)
			requireFailureCode(t, err, failure.CodeTransportFailure)

			if !session.Info().Closed {
				t.Fatal("session remained open after transport connection failure")
			}
			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count = %d, want 1", got)
			}

			_, err = session.Run(context.Background(), model.ConfigStatusOperation{}, nil)
			requireFailureCode(t, err, failure.CodeSessionClosed)

			if err := session.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count after duplicate Close = %d, want 1", got)
			}
		})
	}
}

type transportFailureAuthenticator struct {
	contractAuthenticator
	operation  ctaptransport.IOOperation
	closeCount atomic.Int32
}

func (a *transportFailureAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
	}
}

func (a *transportFailureAuthenticator) SetPIN(context.Context, string) error {
	return &ctaptransport.IOError{
		Operation: a.operation,
		Err:       io.ErrClosedPipe,
	}
}

func (a *transportFailureAuthenticator) Close() error {
	a.closeCount.Add(1)

	return nil
}

func TestSessionEventSinksAreScopedToOpenedSession(t *testing.T) {
	firstEvents := &recordingEventSink{}
	secondEvents := &recordingEventSink{}

	first := openContractSession(t, firstEvents, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return &progressCredentialAuthenticator{}, nil
	})
	if _, err := first.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	firstEventCount := len(firstEvents.Events())
	if firstEventCount == 0 {
		t.Fatal("first session emitted no events")
	}
	if got := len(secondEvents.Events()); got != 0 {
		t.Fatalf("second sink events before second session = %d, want 0", got)
	}

	second := openContractSession(t, secondEvents, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return &progressCredentialAuthenticator{}, nil
	})
	if _, err := second.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if got := len(firstEvents.Events()); got != firstEventCount {
		t.Fatalf("first sink events after second session = %d, want %d", got, firstEventCount)
	}
	if got := len(secondEvents.Events()); got == 0 {
		t.Fatal("second session emitted no events")
	}
}
