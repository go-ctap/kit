package ctapkit

import (
	"context"
	"errors"

	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

func (s *Session) run(
	ctx context.Context,
	operation model.Operation,
	handler model.InteractionHandler,
	opts ...RunOption,
) (model.OperationResult, error) {
	operationKind := ""
	if operation != nil {
		operationKind = string(operation.Kind())
	}

	if err := validateSessionOperationInput(operation); err != nil {
		return nil, normalizeRunError(err, operationKind)
	}

	config, err := newRunConfig(opts...)
	if err != nil {
		return nil, normalizeRunError(err, operationKind)
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
	if err != nil {
		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
			_ = s.core.Close()
		}

		return result, normalizeRunError(err, operationKind)
	}

	return result, nil
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
		return runConfig{}, failure.New(failure.CodeVerificationFlowUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}
}

func validateSessionOperationInput(operation model.Operation) error {
	if operation == nil {
		return failure.New(failure.CodeOperationRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	switch req := operation.(type) {
	case model.SetPINOperation:
		if req.NewPIN == "" {
			return runtimePINRequiredError("newPIN")
		}
	case model.ChangePINOperation:
		if req.CurrentPIN == "" {
			return runtimePINRequiredError("currentPIN")
		}

		if req.NewPIN == "" {
			return runtimePINRequiredError("newPIN")
		}
	}

	return nil
}
