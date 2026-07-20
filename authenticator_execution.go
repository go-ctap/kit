package ctapkit

import (
	"context"
	"errors"

	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/logging"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/internal/workflow"
	appoperation "github.com/go-ctap/kit/model/operation"
)

type workflowCall[T any] func(workflow.Runner, context.Context) (T, error)

func executeOperation[T any](
	a *Authenticator,
	ctx context.Context,
	kind appoperation.Kind,
	call workflowCall[T],
	opts ...OperationOption,
) (*T, error) {
	config, err := newOperationConfig(opts...)
	if err != nil {
		return nil, normalizeRunError(err, string(kind))
	}

	result, err := executeSerializedOperation(a, ctx, kind, config, call)
	if err != nil {
		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
			_ = a.Close()
		}

		return result, normalizeRunError(err, string(kind))
	}

	return result, nil
}

func executeSerializedOperation[T any](
	a *Authenticator,
	ctx context.Context,
	kind appoperation.Kind,
	config operationConfig,
	call workflowCall[T],
) (*T, error) {
	// Invalidated-device cleanup stays in executeOperation: Close also takes
	// runMu, so it must run only after this locked section has returned.
	a.runMu.Lock()
	defer a.runMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	childCtx = logging.WithOperation(childCtx, kind)

	if err := a.start(cancel); err != nil {
		return nil, err
	}
	defer a.finish()

	events := rtruntime.NewEventDispatcher(config.events)
	interactions := rtruntime.NewInteractionBroker(events, config.handler)
	effects := rtruntime.NewStateEffects()
	tokens := rtruntime.NewTokenService(
		a.tokens,
		a.tokenProvider,
		interactions,
		rtruntime.VerificationFlow(config.verificationFlow),
	)
	runner := workflow.NewRunner(workflow.Environment{
		Selected:     a.selected,
		Events:       events,
		Interactions: interactions,
		Tokens:       tokens,
		Effects:      effects,
	})

	result, err := call(runner, childCtx)
	if effects.InvalidatesLargeBlobSnapshot() {
		a.largeBlobState.Clear()
	}

	return &result, err
}
