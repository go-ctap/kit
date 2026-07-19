package ctapkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
)

func TestBioSensorInfoReportsSpecNamedEnums(t *testing.T) {
	tests := []struct {
		name string
		kind uint
		want appconfig.FingerprintKind
	}{
		{
			name: "touch",
			kind: 1,
			want: appconfig.FingerprintKindTouch,
		},
		{
			name: "swipe",
			kind: 2,
			want: appconfig.FingerprintKindSwipe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &bioSensorAuthenticator{
				modality:        protocol.BioModalityFingerprint,
				fingerprintKind: tt.kind,
			}
			session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			output, err := session.BioSensorInfo(context.Background(), session.operationOptions()...)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			if output.Modality != appconfig.BioModalityFingerprint {
				t.Fatalf("modality = %#v, want fingerprint", output.Modality)
			}

			if output.FingerprintKind != tt.want {
				t.Fatalf("fingerprintKind = %#v, want %s", output.FingerprintKind, tt.want)
			}

			raw, err := json.Marshal(output)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			text := string(raw)
			if !strings.Contains(text, `"modality":"fingerprint"`) {
				t.Fatalf("JSON = %s, want string modality", text)
			}

			if !strings.Contains(text, `"fingerprintKind":"`+string(tt.want)+`"`) {
				t.Fatalf("JSON = %s, want string fingerprint kind", text)
			}
		})
	}
}

func TestBioSensorInfoOmitsUnknownSpecValues(t *testing.T) {
	tests := []struct {
		name            string
		modality        protocol.BioModality
		fingerprintKind uint
	}{
		{
			name: "zero",
		},
		{
			name:            "unknown",
			modality:        protocol.BioModality(99),
			fingerprintKind: 99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &bioSensorAuthenticator{
				modality:        tt.modality,
				fingerprintKind: tt.fingerprintKind,
			}
			session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			output, err := session.BioSensorInfo(context.Background(), session.operationOptions()...)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			if output.Modality != "" {
				t.Fatalf("modality = %#v, want empty", output.Modality)
			}

			if output.FingerprintKind != "" {
				t.Fatalf("fingerprintKind = %#v, want empty", output.FingerprintKind)
			}

			raw, err := json.Marshal(output)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			text := string(raw)
			if strings.Contains(text, `"modality"`) || strings.Contains(text, `"fingerprintKind"`) {
				t.Fatalf("JSON = %s, want modality and fingerprintKind omitted", text)
			}
		})
	}
}

func TestResetRequestsTouchInteractionBeforeReset(t *testing.T) {
	events := &recordingEventSink{}
	a := &resetCountingAuthenticator{events: events}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	_, err := session.ResetFactory(
		context.Background(),
		appconfig.ResetFactoryOperation{},
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := a.resetCount.Load(); got != 1 {
		t.Fatalf("Reset count = %d, want 1", got)
	}

	if !a.touchSeenBeforeReset.Load() {
		t.Fatal("touch interaction was not emitted before reset")
	}
}

func TestResetWindowExpiredMapsNotAllowed(t *testing.T) {
	err := runConfirmedResetWithError(t, &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorReset,
		StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED,
	})

	requireFailureCode(t, err, failure.CodeResetWindowExpired)
}

func TestResetTimeoutStatusMapsTimeout(t *testing.T) {
	tests := []ctaptransport.StatusCode{
		ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT,
		ctaptransport.CTAP2_ERR_ACTION_TIMEOUT,
	}

	for _, status := range tests {
		t.Run(status.String(), func(t *testing.T) {
			err := runConfirmedResetWithError(t, &ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorReset,
				StatusCode: status,
			})

			requireFailureCode(t, err, failure.CodeResetTouchTimeout)
		})
	}
}

func TestResetNotAllowedForOtherCommandDoesNotMapWindowExpired(t *testing.T) {
	err := runConfirmedResetWithError(t, &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorMakeCredential,
		StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED,
	})

	requireFailureCode(t, err, failure.CodeAuthenticatorOperationNotAllowed)
}

func TestRunReturnsNormalizedCTAPError(t *testing.T) {
	events := &recordingEventSink{}
	err := runConfirmedResetWithErrorAndEvents(t, events, &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorReset,
		StatusCode: ctaptransport.CTAP2_ERR_ACTION_TIMEOUT,
	})

	requireFailureCode(t, err, failure.CodeResetTouchTimeout)

	if _, ok := errors.AsType[*ctaptransport.CTAPError](err); !ok {
		t.Fatalf("Run error = %v, want original CTAPError in chain", err)
	}
}

func TestRunContextReachesTokenAndAuthenticatorCommand(t *testing.T) {
	type contextKey struct{}

	a := &contextRecordingConfigAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	marker := new(int)
	ctx := context.WithValue(context.Background(), contextKey{}, marker)
	if _, err := session.SetAlwaysUV(
		ctx,
		appconfig.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable},
		WithInteractionHandler(userVerificationHandler(t)),
	); err != nil {
		t.Fatalf("SetAlwaysUV: %v", err)
	}

	if got := a.tokenCtx.Value(contextKey{}); got != marker {
		t.Fatalf("token context value = %v, want marker", got)
	}

	if got := a.commandCtx.Value(contextKey{}); got != marker {
		t.Fatalf("command context value = %v, want marker", got)
	}
}

func TestBioEnrollmentCleanupUsesBoundedIndependentContext(t *testing.T) {
	type contextKey struct{}

	operationErr := errors.New("capture failed")
	cleanupErr := context.DeadlineExceeded
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "marker"))
	a := &bioCleanupAuthenticator{
		cancelOperation: cancel,
		captureErr:      operationErr,
		cleanupErr:      cleanupErr,
	}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	result, err := session.BioEnroll(
		ctx,
		appconfig.BioEnrollOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !errors.Is(err, operationErr) {
		t.Fatalf("Run error = %v, want original capture error", err)
	}

	if result.Result == nil || !result.Result.CancelAttempted || result.Result.CancelSucceeded {
		t.Fatalf("bio result = %#v, want failed cleanup attempt", result.Result)
	}

	if a.cleanupCtx == nil {
		t.Fatal("cleanup context was not recorded")
	}

	if err := a.cleanupContextErr; err != nil {
		t.Fatalf("cleanup context was already canceled during command: %v", err)
	}

	if got := a.cleanupCtx.Value(contextKey{}); got != "marker" {
		t.Fatalf("cleanup context value = %v, want marker", got)
	}

	deadline, ok := a.cleanupCtx.Deadline()
	if !ok {
		t.Fatal("cleanup context has no deadline")
	}

	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("cleanup deadline remaining = %v, want within two seconds", remaining)
	}
}

func TestBioEnrollmentSuccessfulCleanupIsReported(t *testing.T) {
	operationErr := errors.New("capture failed")
	a := &bioCleanupAuthenticator{captureErr: operationErr}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	result, err := session.BioEnroll(
		context.Background(),
		appconfig.BioEnrollOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !errors.Is(err, operationErr) {
		t.Fatalf("Run error = %v, want original capture error", err)
	}

	if result.Result == nil || !result.Result.CancelAttempted || !result.Result.CancelSucceeded {
		t.Fatalf("bio result = %#v, want successful cleanup", result.Result)
	}
}

func runConfirmedResetWithError(t *testing.T, resetErr error) error {
	t.Helper()

	events := &recordingEventSink{}
	return runConfirmedResetWithErrorAndEvents(t, events, resetErr)
}

func runConfirmedResetWithErrorAndEvents(t *testing.T, events *recordingEventSink, resetErr error) error {
	t.Helper()

	a := &resetCountingAuthenticator{events: events, resetErr: resetErr}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	_, err := session.ResetFactory(
		context.Background(),
		appconfig.ResetFactoryOperation{},
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	if err == nil {
		t.Fatal("Run error = nil, want error")
	}

	return err
}

type contextRecordingConfigAuthenticator struct {
	contractAuthenticator
	tokenCtx   context.Context
	commandCtx context.Context
}

func (a *contextRecordingConfigAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionAuthenticatorConfig: true,
		protocol.OptionPinUvAuthToken:      true,
		protocol.OptionUserVerification:    true,
		protocol.OptionUvAcfg:              true,
		protocol.OptionAlwaysUv:            false,
	}}
}

func (a *contextRecordingConfigAuthenticator) GetPinUvAuthTokenUsingUV(
	ctx context.Context,
	_ protocol.Permission,
	_ string,
) ([]byte, error) {
	a.tokenCtx = ctx

	return []byte("token"), nil
}

func (a *contextRecordingConfigAuthenticator) ToggleAlwaysUV(ctx context.Context, token []byte) error {
	if token == nil {
		return ctapdevice.ErrPinUvAuthTokenRequired
	}

	a.commandCtx = ctx

	return nil
}

type bioCleanupAuthenticator struct {
	contractAuthenticator
	cancelOperation   context.CancelFunc
	captureErr        error
	cleanupErr        error
	cleanupCtx        context.Context
	cleanupContextErr error
}

func (a *bioCleanupAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionBioEnroll:        true,
		protocol.OptionUvBioEnroll:      true,
		protocol.OptionPinUvAuthToken:   true,
		protocol.OptionUserVerification: true,
	}}
}

func (a *bioCleanupAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *bioCleanupAuthenticator) EnrollBegin(context.Context, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	remaining := uint(1)

	return protocol.AuthenticatorBioEnrollmentResponse{
		TemplateID:       []byte("template"),
		RemainingSamples: &remaining,
	}, nil
}

func (a *bioCleanupAuthenticator) EnrollCaptureNextSample(context.Context, []byte, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if a.cancelOperation != nil {
		a.cancelOperation()
	}

	return protocol.AuthenticatorBioEnrollmentResponse{}, a.captureErr
}

func (a *bioCleanupAuthenticator) CancelCurrentEnrollment(ctx context.Context) error {
	a.cleanupCtx = ctx
	a.cleanupContextErr = ctx.Err()

	return a.cleanupErr
}

type bioSensorAuthenticator struct {
	contractAuthenticator
	modality        protocol.BioModality
	fingerprintKind uint
}

func (a *bioSensorAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll: true,
		},
	}
}

func (a *bioSensorAuthenticator) GetBioModality(context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{Modality: a.modality}, nil
}

func (a *bioSensorAuthenticator) GetFingerprintSensorInfo(context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{FingerprintKind: a.fingerprintKind}, nil
}

func TestPINMutationsRejectEmptyPINAtSessionRun(t *testing.T) {
	tests := []struct {
		name       string
		configured bool
		invoke     func(*contractAuthenticatorHandle) (*appconfig.PINOutput, error)
		wantSet    int32
		wantChange int32
	}{
		{
			name: "set empty new PIN",
			invoke: func(session *contractAuthenticatorHandle) (*appconfig.PINOutput, error) {
				return session.SetPIN(
					context.Background(),
					appconfig.SetPINOperation{},
					session.operationOptions()...,
				)
			},
		},
		{
			name:       "change empty current PIN",
			configured: true,
			invoke: func(session *contractAuthenticatorHandle) (*appconfig.PINOutput, error) {
				return session.ChangePIN(
					context.Background(),
					appconfig.ChangePINOperation{NewPIN: "5678"},
					session.operationOptions()...,
				)
			},
		},
		{
			name:       "change empty new PIN",
			configured: true,
			invoke: func(session *contractAuthenticatorHandle) (*appconfig.PINOutput, error) {
				return session.ChangePIN(
					context.Background(),
					appconfig.ChangePINOperation{CurrentPIN: "1234"},
					session.operationOptions()...,
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &pinMutationCountingAuthenticator{configured: tt.configured}
			session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			result, err := tt.invoke(session)
			if result != nil {
				t.Fatalf("result = %#v, want nil", result)
			}

			requireFailureCode(t, err, failure.CodePINRequired)

			if got := a.setCalls.Load(); got != tt.wantSet {
				t.Fatalf("SetPIN calls = %d, want %d", got, tt.wantSet)
			}

			if got := a.changeCalls.Load(); got != tt.wantChange {
				t.Fatalf("ChangePIN calls = %d, want %d", got, tt.wantChange)
			}
		})
	}
}

func TestUVTokenAcquisitionRequestsUserVerificationInteraction(t *testing.T) {
	events := &recordingEventSink{}
	a := &uvTokenAuthenticator{events: events}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindUserVerification {
			t.Fatalf("interaction kind = %s, want user-verification", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	result, err := session.SetAlwaysUV(context.Background(), appconfig.SetAlwaysUVOperation{
		Target: appconfig.AlwaysUVTargetEnable,
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result == nil {
		t.Fatal("result = nil, want output")
	}

	if !a.uvCalled.Load() {
		t.Fatal("GetPinUvAuthTokenUsingUV was not called")
	}

	if !a.userVerificationSeen.Load() {
		t.Fatal("user-verification interaction was not emitted before UV token acquisition")
	}
}
