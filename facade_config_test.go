package ctapkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
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
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			output, err := session.Run(context.Background(), model.BioSensorInfoOperation{}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			typed, ok := output.(model.BioSensorOutput)
			if !ok {
				t.Fatalf("output = %#v, want BioSensorOutput", output)
			}
			if typed.Report.Modality == nil || *typed.Report.Modality != appconfig.BioModalityFingerprint {
				t.Fatalf("modality = %#v, want fingerprint", typed.Report.Modality)
			}
			if typed.Report.FingerprintKind == nil || *typed.Report.FingerprintKind != tt.want {
				t.Fatalf("fingerprintKind = %#v, want %s", typed.Report.FingerprintKind, tt.want)
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
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			output, err := session.Run(context.Background(), model.BioSensorInfoOperation{}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			typed, ok := output.(model.BioSensorOutput)
			if !ok {
				t.Fatalf("output = %#v, want BioSensorOutput", output)
			}
			if typed.Report.Modality != nil {
				t.Fatalf("modality = %#v, want nil", typed.Report.Modality)
			}
			if typed.Report.FingerprintKind != nil {
				t.Fatalf("fingerprintKind = %#v, want nil", typed.Report.FingerprintKind)
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

func TestBioSensorInfoUnsupportedReturnsSentinel(t *testing.T) {
	session := openContractSession(t, nil, nil)
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.BioSensorInfoOperation{}, nil)
	if !errors.Is(err, appconfig.ErrBioUnsupported) {
		t.Fatalf("Run error = %v, want ErrBioUnsupported", err)
	}
}

func TestResetDeclinedConfirmDoesNotEmitTouchOrReset(t *testing.T) {
	a := &resetCountingAuthenticator{}
	events := &recordingEventSink{}
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

		return model.InteractionResponse{}, nil
	})

	_, err := session.Run(context.Background(), model.ResetFactoryOperation{}, handler)
	if !errors.Is(err, appconfig.ErrConfirmationRequired) {
		t.Fatalf("Run error = %v, want confirmation required", err)
	}

	if got := a.resetCount.Load(); got != 0 {
		t.Fatalf("Reset count = %d, want 0", got)
	}

	for _, event := range events.Events() {
		if event.Kind == model.InteractionKindTouch {
			t.Fatal("touch interaction emitted for invalid reset phrase")
		}
	}
}

func TestResetRequestsTouchInteractionBeforeReset(t *testing.T) {
	events := &recordingEventSink{}
	a := &resetCountingAuthenticator{events: events}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	_, err := session.Run(context.Background(), model.ResetFactoryOperation{
		Confirmed: true,
	}, handler)
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
	err := runConfirmedResetWithError(t, &ctaphid.CTAPError{
		Command:    protocol.AuthenticatorReset,
		StatusCode: ctaphid.CTAP2_ERR_NOT_ALLOWED,
	})

	if !model.IsErrorCategory(err, model.ErrorInvalidState) {
		t.Fatalf("Run error = %v, want invalid-state", err)
	}

	if !errors.Is(err, appconfig.ErrResetWindowExpired) {
		t.Fatalf("Run error = %v, want reset window expired sentinel", err)
	}
}

func TestResetTimeoutStatusMapsTimeout(t *testing.T) {
	tests := []ctaphid.StatusCode{
		ctaphid.CTAP2_ERR_USER_ACTION_TIMEOUT,
		ctaphid.CTAP2_ERR_ACTION_TIMEOUT,
	}

	for _, status := range tests {
		t.Run(status.String(), func(t *testing.T) {
			err := runConfirmedResetWithError(t, &ctaphid.CTAPError{
				Command:    protocol.AuthenticatorReset,
				StatusCode: status,
			})

			if !model.IsErrorCategory(err, model.ErrorTimeout) {
				t.Fatalf("Run error = %v, want timeout", err)
			}
		})
	}
}

func TestResetNotAllowedForOtherCommandDoesNotMapWindowExpired(t *testing.T) {
	err := runConfirmedResetWithError(t, &ctaphid.CTAPError{
		Command:    protocol.AuthenticatorMakeCredential,
		StatusCode: ctaphid.CTAP2_ERR_NOT_ALLOWED,
	})

	if errors.Is(err, appconfig.ErrResetWindowExpired) {
		t.Fatalf("Run error = %v, should not match reset window expired sentinel", err)
	}

	if !model.IsErrorCategory(err, model.ErrorInvalidState) {
		t.Fatalf("Run error = %v, want invalid-state", err)
	}
}

func TestRunReturnsNormalizedCTAPErrorCategory(t *testing.T) {
	events := &recordingEventSink{}
	err := runConfirmedResetWithErrorAndEvents(t, events, &ctaphid.CTAPError{
		Command:    protocol.AuthenticatorReset,
		StatusCode: ctaphid.CTAP2_ERR_ACTION_TIMEOUT,
	})

	if !model.IsErrorCategory(err, model.ErrorTimeout) {
		t.Fatalf("Run error = %v, want timeout", err)
	}

	if _, ok := errors.AsType[*ctaphid.CTAPError](err); !ok {
		t.Fatalf("Run error = %v, want original CTAPError in chain", err)
	}
}

func TestPINMutationCTAPStatusMapsSentinel(t *testing.T) {
	tests := []struct {
		name      string
		operation model.Operation
		auth      *pinMutationCountingAuthenticator
		want      error
	}{
		{
			name:      "set PIN policy violation",
			operation: model.SetPINOperation{NewPIN: "1234", Confirmed: true},
			auth: &pinMutationCountingAuthenticator{
				setErr: &ctaphid.CTAPError{
					Command:    protocol.AuthenticatorClientPIN,
					StatusCode: ctaphid.CTAP2_ERR_PIN_POLICY_VIOLATION,
				},
			},
			want: appconfig.ErrPINPolicyViolation,
		},
		{
			name:      "change invalid PIN",
			operation: model.ChangePINOperation{CurrentPIN: "1234", NewPIN: "5678", Confirmed: true},
			auth: &pinMutationCountingAuthenticator{
				configured: true,
				changeErr: &ctaphid.CTAPError{
					Command:    protocol.AuthenticatorClientPIN,
					StatusCode: ctaphid.CTAP2_ERR_PIN_INVALID,
				},
			},
			want: appconfig.ErrPINInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return tt.auth, nil
			})
			defer func() { _ = session.Close() }()

			_, err := session.Run(context.Background(), tt.operation, nil)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Run error = %v, want sentinel %v", err, tt.want)
			}
			if !model.IsErrorCategory(err, model.ErrorInvalidState) {
				t.Fatalf("Run category = %v, want invalid-state", err)
			}
		})
	}
}

func TestBioEnrollmentCTAPStatusMapsSentinel(t *testing.T) {
	tests := []struct {
		name      string
		operation model.Operation
		auth      *bioErrorAuthenticator
		want      error
	}{
		{
			name:      "database full",
			operation: model.BioEnrollOperation{Confirmed: true},
			auth: &bioErrorAuthenticator{
				beginErr: &ctaphid.CTAPError{
					Command:    protocol.AuthenticatorBioEnrollment,
					StatusCode: ctaphid.CTAP2_ERR_FP_DATABASE_FULL,
				},
			},
			want: appconfig.ErrBioDatabaseFull,
		},
		{
			name:      "template missing",
			operation: model.BioRemoveOperation{TemplateIDHex: "c05e", Confirmed: true},
			auth: &bioErrorAuthenticator{
				removeErr: &ctaphid.CTAPError{
					Command:    protocol.AuthenticatorBioEnrollment,
					StatusCode: ctaphid.CTAP2_ERR_INVALID_OPTION,
				},
			},
			want: appconfig.ErrBioEnrollmentNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return tt.auth, nil
			})
			defer func() { _ = session.Close() }()

			_, err := session.Run(context.Background(), tt.operation, userVerificationHandler(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Run error = %v, want sentinel %v", err, tt.want)
			}
			if !model.IsErrorCategory(err, model.ErrorInvalidState) {
				t.Fatalf("Run category = %v, want invalid-state", err)
			}
		})
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
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	_, err := session.Run(context.Background(), model.ResetFactoryOperation{Confirmed: true}, handler)
	if err == nil {
		t.Fatal("Run error = nil, want error")
	}

	return err
}

type bioErrorAuthenticator struct {
	contractAuthenticator
	beginErr  error
	removeErr error
}

func (a *bioErrorAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll:        true,
			protocol.OptionUvBioEnroll:      true,
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
		},
	}
}

func (a *bioErrorAuthenticator) GetPinUvAuthTokenUsingUV(protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *bioErrorAuthenticator) EnrollBegin([]byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, a.beginErr
}

func (a *bioErrorAuthenticator) RemoveEnrollment([]byte, []byte) error {
	return a.removeErr
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

func (a *bioSensorAuthenticator) GetBioModality() (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{Modality: &a.modality}, nil
}

func (a *bioSensorAuthenticator) GetFingerprintSensorInfo() (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{FingerprintKind: &a.fingerprintKind}, nil
}

func TestPINMutationsRejectEmptyPINAtSessionRun(t *testing.T) {
	tests := []struct {
		name       string
		configured bool
		operation  model.Operation
		wantSet    int32
		wantChange int32
	}{
		{
			name:      "set empty new PIN",
			operation: model.SetPINOperation{Confirmed: true},
		},
		{
			name:       "change empty current PIN",
			configured: true,
			operation:  model.ChangePINOperation{NewPIN: "5678", Confirmed: true},
		},
		{
			name:       "change empty new PIN",
			configured: true,
			operation:  model.ChangePINOperation{CurrentPIN: "1234", Confirmed: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &pinMutationCountingAuthenticator{configured: tt.configured}
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			result, err := session.Run(context.Background(), tt.operation, nil)
			if result != nil {
				t.Fatalf("result = %#v, want nil", result)
			}

			if !errors.Is(err, appconfig.ErrPINRequired) {
				t.Fatalf("Run error = %v, want ErrPINRequired", err)
			}

			if !model.IsErrorCategory(err, model.ErrorInvalidOperation) {
				t.Fatalf("Start category = %v, want invalid-operation", err)
			}

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
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindUserVerification {
			t.Fatalf("interaction kind = %s, want user-verification", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	result, err := session.Run(context.Background(), model.SetAlwaysUVOperation{
		Target:    appconfig.AlwaysUVTargetEnable,
		Confirmed: true,
	}, handler)
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
