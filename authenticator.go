package ctapkit

import (
	"context"
	"sync"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/logging"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
)

type AuthenticatorOption func(*authenticatorConfig)

type authenticatorConfig struct {
	journal *LogJournal
}

type OperationOption func(*operationConfig)

type operationConfig struct {
	verificationFlow model.VerificationFlow
	events           model.EventSink
}

func WithEventSink(events model.EventSink) OperationOption {
	return func(config *operationConfig) {
		config.events = events
	}
}

func WithLogJournal(journal *LogJournal) AuthenticatorOption {
	return func(config *authenticatorConfig) {
		config.journal = journal
	}
}

func WithVerificationFlow(flow model.VerificationFlow) OperationOption {
	return func(config *operationConfig) {
		config.verificationFlow = flow
	}
}

// Authenticator is one opened authenticator channel. It owns transport
// lifecycle, operation serialization, and runtime token state until Close.
type Authenticator struct {
	selected report.DeviceReport
	device   authenticator.Device
	tokens   *rtruntime.TokenStore

	runMu   sync.Mutex
	stateMu sync.Mutex
	closed  bool
	cancel  context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

func OpenAuthenticator(
	ctx context.Context,
	device Device,
	opts ...AuthenticatorOption,
) (*Authenticator, error) {
	return openAuthenticatorHandle(ctx, device, openAuthenticator, opts...)
}

func openAuthenticatorHandle(
	ctx context.Context,
	device Device,
	open authenticatorOpenFunc,
	opts ...AuthenticatorOption,
) (*Authenticator, error) {
	var config authenticatorConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}

	if !device.valid {
		return nil, failure.New(failure.CodeDeviceHandleInvalid,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}

	var recorder logging.Recorder
	if config.journal != nil {
		recorder = config.journal.journal
	}
	selected := device.report
	opened, err := open(logging.WithRecorder(ctx, recorder), selected.Transport, selected.Path)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		selected: selected,
		device:   opened,
		tokens:   rtruntime.NewTokenStore(),
	}, nil
}

func (a *Authenticator) Close() error {
	a.stateMu.Lock()
	a.closed = true

	if a.cancel != nil {
		a.cancel()
	}
	a.stateMu.Unlock()

	a.closeOnce.Do(func() {
		a.runMu.Lock()
		defer a.runMu.Unlock()

		a.tokens.InvalidateToken()

		if a.device != nil {
			a.closeErr = a.device.Close()
		}
	})

	if a.closeErr != nil {
		return normalizeBoundaryError(a.closeErr, failure.PhaseCleanup)
	}

	return nil
}

func (a *Authenticator) Device() report.DeviceReport {
	return a.selected
}

func (a *Authenticator) Closed() bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	return a.closed
}

func (a *Authenticator) start(cancel context.CancelFunc) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	if a.closed {
		return failure.New(failure.CodeAuthenticatorClosed,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}

	a.cancel = cancel

	return nil
}

func (a *Authenticator) finish() {
	a.stateMu.Lock()
	a.cancel = nil
	a.stateMu.Unlock()
}

func newOperationConfig(opts ...OperationOption) (operationConfig, error) {
	var config operationConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}

	switch config.verificationFlow {
	case model.VerificationFlowDefault, model.VerificationFlowPIN:
		return config, nil
	default:
		return operationConfig{}, failure.New(failure.CodeVerificationFlowUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}
}
