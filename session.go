package ctapkit

import (
	"context"

	rtsession "github.com/go-ctap/kit/internal/session"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

type OpenSessionOption func(*openSessionConfig)

type openSessionConfig struct {
	events            model.EventSink
	strictPermissions bool
}

type RunOption func(*runConfig)

type runConfig struct {
	verificationFlow model.VerificationFlow
}

func WithEventSink(events model.EventSink) OpenSessionOption {
	return func(config *openSessionConfig) {
		config.events = events
	}
}

// WithStrictPermissions scopes credential management mutation tokens to the
// target RP ID for credentials.delete and credentials.updateUser operations.
func WithStrictPermissions() OpenSessionOption {
	return func(config *openSessionConfig) {
		config.strictPermissions = true
	}
}

func WithVerificationFlow(flow model.VerificationFlow) RunOption {
	return func(config *runConfig) {
		config.verificationFlow = flow
	}
}

type Session struct {
	core *rtsession.Core
}

type sessionDependencies struct {
	openAuthenticator authenticatorOpenFunc
}

func OpenSession(ctx context.Context, dev Device, opts ...OpenSessionOption) (*Session, error) {
	return openSession(ctx, dev, defaultSessionDependencies(), opts...)
}

func defaultSessionDependencies() sessionDependencies {
	return sessionDependencies{
		openAuthenticator: openAuthenticator,
	}
}

func openSession(
	ctx context.Context,
	dev Device,
	deps sessionDependencies,
	opts ...OpenSessionOption,
) (*Session, error) {
	config := &openSessionConfig{
		events: model.NoopEventSink{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(config)
		}
	}
	if config.events == nil {
		config.events = model.NoopEventSink{}
	}

	if !dev.valid {
		return nil, failure.New(failure.CodeDeviceHandleInvalid,
			failure.WithPhase(failure.PhaseSession),
		)
	}
	selected := dev.report

	authenticator, err := deps.openAuthenticator(ctx, selected.Transport, selected.Path)
	if err != nil {
		return nil, err
	}

	return &Session{
		core: rtsession.New(selected, authenticator, config.events, config.strictPermissions),
	}, nil
}

func (s *Session) Run(
	ctx context.Context,
	operation model.Operation,
	handler model.InteractionHandler,
	opts ...RunOption,
) (model.OperationResult, error) {
	return s.run(ctx, operation, handler, opts...)
}

func (s *Session) Close() error {
	if err := s.core.Close(); err != nil {
		return normalizeBoundaryError(err, failure.PhaseCleanup)
	}

	return nil
}

func (s *Session) Info() model.SessionInfo {
	return s.core.Info()
}
