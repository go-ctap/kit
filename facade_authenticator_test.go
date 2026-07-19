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
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/operation"
	"github.com/go-ctap/kit/transport"
)

func TestAuthenticatorTypedOperationContract(t *testing.T) {
	opened := openContractAuthenticator(t, nil, nil)
	defer func() { _ = opened.Close() }()

	output, err := opened.ConfigStatus(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("ConfigStatus: %v", err)
	}

	if output.Device.Fingerprint == "" {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestAuthenticatorPreCompletedContextHasAuthenticatorPhase(t *testing.T) {
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

	opened := openContractAuthenticator(t, nil, nil)
	defer func() { _ = opened.Close() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := opened.ConfigStatus(tt.ctx, nil)
			requireFailureCode(t, err, tt.code)

			snapshot := failure.Snapshot(err)
			if snapshot.Operation != string(operation.ConfigStatus) {
				t.Fatalf("operation = %q, want %q", snapshot.Operation, operation.ConfigStatus)
			}

			if snapshot.Phase != failure.PhaseAuthenticator {
				t.Fatalf("phase = %q, want %q", snapshot.Phase, failure.PhaseAuthenticator)
			}
		})
	}
}

func TestAuthenticatorCloseClosesAuthenticatorOnce(t *testing.T) {
	a := &closeCountingAuthenticator{
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	opened := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = opened.Close() }()

	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)

	go func() {
		firstErr <- opened.Close()
	}()

	<-a.closeStarted

	go func() {
		secondErr <- opened.Close()
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

func TestAuthenticatorCloseCancelsActiveRunAndClosesAuthenticatorOnce(t *testing.T) {
	events := &recordingEventSink{}
	a := &cancelablePINAuthenticator{
		pinOnlyLargeBlobWriteEventAuthenticator: pinOnlyLargeBlobWriteEventAuthenticator{
			largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
		},
		closeStarted: make(chan struct{}),
	}
	opened := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})

	interactionEntered := make(chan struct{})
	runDone := make(chan error, 1)
	handler := contextualInteractionHandlerFunc(func(ctx context.Context, _ model.InteractionRequest) (model.InteractionResponse, error) {
		close(interactionEntered)
		<-ctx.Done()

		return model.InteractionResponse{}, ctx.Err()
	})

	go func() {
		_, err := opened.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("test"),
		}, opened.operationOptions(WithInteractionHandler(handler))...)
		runDone <- err
	}()

	select {
	case <-interactionEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach PIN interaction")
	}

	closeDone := make(chan error, 2)

	go func() { closeDone <- opened.Close() }()

	select {
	case <-a.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Authenticator.Close did not close authenticator")
	}

	go func() { closeDone <- opened.Close() }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Authenticator.Close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Authenticator.Close did not return")
		}
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("Run was not canceled by Authenticator.Close")
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestAuthenticatorCloseCancelsContextAwareInteractionHandler(t *testing.T) {
	events := &recordingEventSink{}
	a := &cancelablePINAuthenticator{
		pinOnlyLargeBlobWriteEventAuthenticator: pinOnlyLargeBlobWriteEventAuthenticator{
			largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
		},
		closeStarted: make(chan struct{}),
	}
	opened := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})

	interactionEntered := make(chan struct{})
	runDone := make(chan error, 1)
	handler := contextualInteractionHandlerFunc(func(ctx context.Context, _ model.InteractionRequest) (model.InteractionResponse, error) {
		close(interactionEntered)
		<-ctx.Done()

		return model.InteractionResponse{}, ctx.Err()
	})

	go func() {
		_, err := opened.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("test"),
		}, opened.operationOptions(WithInteractionHandler(handler))...)
		runDone <- err
	}()

	select {
	case <-interactionEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach PIN interaction")
	}

	closeDone := make(chan error, 1)

	go func() { closeDone <- opened.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Authenticator.Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Authenticator.Close waited for canceled interaction handler")
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("Run was not canceled by Authenticator.Close")
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestAuthenticatorCloseCancelsBlockedAuthenticatorCommand(t *testing.T) {
	a := &blockingConfigAuthenticator{commandEntered: make(chan struct{})}
	opened := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = opened.Close() }()

	runDone := make(chan error, 1)
	go func() {
		_, err := opened.SetAlwaysUV(
			context.Background(),
			appconfig.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable},
			opened.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
		)
		runDone <- err
	}()

	select {
	case <-a.commandEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach authenticator command")
	}

	if err := opened.Close(); err != nil {
		t.Fatalf("Authenticator.Close: %v", err)
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("blocked authenticator command did not observe cancellation")
	}
}

func TestRunAfterAuthenticatorCloseIsRejected(t *testing.T) {
	opened := openContractAuthenticator(t, nil, nil)

	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := opened.ConfigStatus(context.Background(), opened.operationOptions()...)
	requireFailureCode(t, err, failure.CodeAuthenticatorClosed)

	if result != nil {
		t.Fatalf("result = %#v, want nil", result)
	}
}

func TestTransportConnectionFailureClosesAuthenticator(t *testing.T) {
	tests := []ctaptransport.IOOperation{
		ctaptransport.IORead,
		ctaptransport.IOWrite,
		ctaptransport.IOTransmit,
	}

	for _, operation := range tests {
		t.Run(string(operation), func(t *testing.T) {
			a := &transportFailureAuthenticator{
				operation:   operation,
				invalidated: true,
			}
			opened := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})

			_, err := opened.SetPIN(context.Background(), appconfig.SetPINOperation{
				NewPIN: "1234",
			}, opened.operationOptions()...)
			requireFailureCode(t, err, failure.CodeTransportFailure)

			if !opened.Closed() {
				t.Fatal("opened remained open after transport connection failure")
			}

			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count = %d, want 1", got)
			}

			_, err = opened.ConfigStatus(context.Background(), opened.operationOptions()...)
			requireFailureCode(t, err, failure.CodeAuthenticatorClosed)

			if err := opened.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count after duplicate Close = %d, want 1", got)
			}
		})
	}
}

func TestTransportFailureWithoutDeviceInvalidationKeepsAuthenticatorOpen(t *testing.T) {
	tests := []ctaptransport.IOOperation{
		ctaptransport.IORead,
		ctaptransport.IOWrite,
		ctaptransport.IOTransmit,
	}

	for _, operation := range tests {
		t.Run(string(operation), func(t *testing.T) {
			a := &transportFailureAuthenticator{operation: operation}
			opened := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})

			_, err := opened.SetPIN(context.Background(), appconfig.SetPINOperation{
				NewPIN: "1234",
			}, opened.operationOptions()...)
			requireFailureCode(t, err, failure.CodeTransportFailure)

			if opened.Closed() {
				t.Fatal("opened closed without device invalidation")
			}

			if got := a.closeCount.Load(); got != 0 {
				t.Fatalf("authenticator close count = %d, want 0", got)
			}

			if err := opened.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count after Close = %d, want 1", got)
			}
		})
	}
}

func TestCanceledTransmitWithoutDeviceInvalidationKeepsAuthenticatorOpen(t *testing.T) {
	a := &transportFailureAuthenticator{
		operation: ctaptransport.IOTransmit,
		cause:     context.Canceled,
	}
	opened := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = opened.Close() }()

	_, err := opened.SetPIN(context.Background(), appconfig.SetPINOperation{
		NewPIN: "1234",
	}, opened.operationOptions()...)
	requireFailureCode(t, err, failure.CodeOperationCanceled)

	if opened.Closed() {
		t.Fatal("opened closed after a canceled transmit without device invalidation")
	}

	if got := a.closeCount.Load(); got != 0 {
		t.Fatalf("authenticator close count = %d, want 0", got)
	}
}

type transportFailureAuthenticator struct {
	contractAuthenticator
	operation   ctaptransport.IOOperation
	cause       error
	invalidated bool
	closeCount  atomic.Int32
}

func (a *transportFailureAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
	}
}

func (a *transportFailureAuthenticator) SetPIN(context.Context, string) error {
	cause := a.cause
	if cause == nil {
		cause = io.ErrClosedPipe
	}
	err := &ctaptransport.IOError{
		Operation: a.operation,
		Err:       cause,
	}

	if a.invalidated {
		return &ctaptransport.DeviceInvalidatedError{Err: err}
	}

	return err
}

func (a *transportFailureAuthenticator) Close() error {
	a.closeCount.Add(1)

	return nil
}

func TestAuthenticatorEventSinksAreScopedToRun(t *testing.T) {
	firstEvents := &recordingEventSink{}
	secondEvents := &recordingEventSink{}

	opened := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return &progressCredentialAuthenticator{}, nil
	})
	defer func() { _ = opened.Close() }()

	if _, err := opened.Authenticator.ListCredentials(
		context.Background(),
		WithInteractionHandler(userVerificationHandler(t)),
		WithEventSink(firstEvents),
	); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	firstEventCount := len(firstEvents.Events())
	if firstEventCount == 0 {
		t.Fatal("first opened emitted no events")
	}

	if got := len(secondEvents.Events()); got != 0 {
		t.Fatalf("second sink events before second run = %d, want 0", got)
	}

	if _, err := opened.Authenticator.ListCredentials(
		context.Background(),
		WithInteractionHandler(userVerificationHandler(t)),
		WithEventSink(secondEvents),
	); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	if got := len(firstEvents.Events()); got != firstEventCount {
		t.Fatalf("first sink events after second run = %d, want %d", got, firstEventCount)
	}

	if got := len(secondEvents.Events()); got == 0 {
		t.Fatal("second run emitted no events")
	}
}
