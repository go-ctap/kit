package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/logging"
	rtsession "github.com/go-ctap/kit/internal/session"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

type OpenSessionOption func(*openSessionConfig)

type openSessionConfig struct {
	events            model.EventSink
	journal           *LogJournal
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

func WithLogJournal(journal *LogJournal) OpenSessionOption {
	return func(config *openSessionConfig) {
		config.journal = journal
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

func OpenSession(ctx context.Context, dev Device, opts ...OpenSessionOption) (*Session, error) {
	return openSession(ctx, dev, openAuthenticator, opts...)
}

func openSession(
	ctx context.Context,
	dev Device,
	open authenticatorOpenFunc,
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

	var recorder logging.Recorder
	if config.journal != nil {
		recorder = config.journal.journal
	}
	device, err := open(logging.WithRecorder(ctx, recorder), selected.Transport, selected.Path)
	if err != nil {
		return nil, err
	}

	return &Session{
		core: rtsession.New(selected, device, config.events, config.strictPermissions),
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
