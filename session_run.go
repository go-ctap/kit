package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
)

func (s *Session) run(
	ctx context.Context,
	operation model.Operation,
	handler model.InteractionHandler,
	opts ...RunOption,
) (model.OperationResult, error) {
	if err := validateSessionOperationInput(operation); err != nil {
		return nil, err
	}

	config, err := newRunConfig(opts...)
	if err != nil {
		return nil, err
	}

	result, err := s.core.RunSerializedWorkflow(ctx, func(ctx context.Context) (model.OperationResult, error) {
		interactions := s.core.InteractionBroker(handler)
		tokens := s.core.TokenService(interactions, config.verificationFlow)

		return workflow.Run(ctx, workflow.Environment{
			Selected:          s.core.SelectedDevice(),
			Authenticator:     s.core.Authenticator(),
			Events:            s.core.EventSink(),
			Interactions:      interactions,
			Cache:             s.core.Cache(),
			Tokens:            tokens,
			StrictPermissions: s.core.StrictPermissions(),
		}, operation)
	})
	err = normalizeRunError(err)

	return result, err
}

func newRunConfig(opts ...RunOption) (runConfig, error) {
	var config runConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}

	switch config.verificationFlow {
	case model.VerificationFlowDefault, model.VerificationFlowPIN:
		return config, nil
	default:
		return runConfig{}, model.NewRuntimeError(
			model.ErrorInvalidOperation,
			"unsupported verification flow",
			nil,
		)
	}
}

func validateSessionOperationInput(operation model.Operation) error {
	if operation == nil {
		return model.NewRuntimeError(model.ErrorInvalidOperation, "operation is required", nil)
	}

	switch req := operation.(type) {
	case model.SetPINOperation:
		if req.NewPIN == "" {
			return runtimePINRequiredError("new PIN")
		}
	case model.ChangePINOperation:
		if req.CurrentPIN == "" {
			return runtimePINRequiredError("current PIN")
		}

		if req.NewPIN == "" {
			return runtimePINRequiredError("new PIN")
		}
	}

	return nil
}
