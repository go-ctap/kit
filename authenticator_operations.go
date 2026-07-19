package ctapkit

import (
	"context"
	"errors"

	ctaptransport "github.com/go-ctap/ctap/transport"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
)

type workflowCall[T any] func(workflow.Runner, context.Context) (T, error)

func executeOperation[T any](
	a *Authenticator,
	ctx context.Context,
	kind model.OperationKind,
	handler model.InteractionHandler,
	call workflowCall[T],
	opts ...OperationOption,
) (*T, error) {
	config, err := newOperationConfig(opts...)
	if err != nil {
		return nil, normalizeRunError(err, string(kind))
	}

	result, err := executeOperationBody(a, ctx, handler, config, call)
	if err != nil {
		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
			_ = a.Close()
		}

		return result, normalizeRunError(err, string(kind))
	}

	return result, nil
}

func executeOperationBody[T any](
	a *Authenticator,
	ctx context.Context,
	handler model.InteractionHandler,
	config operationConfig,
	call workflowCall[T],
) (*T, error) {
	a.runMu.Lock()
	defer a.runMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := a.start(cancel); err != nil {
		return nil, err
	}
	defer a.finish()

	events := rtruntime.NewEventDispatcher(config.events)
	interactions := rtruntime.NewInteractionBroker(events, handler)
	tokens := rtruntime.NewTokenService(a.tokens, a.device, interactions, config.verificationFlow)
	runner := workflow.NewRunner(workflow.Environment{
		Selected:      a.selected,
		Authenticator: a.device,
		Events:        events,
		Interactions:  interactions,
		Tokens:        tokens,
	})

	result, err := call(runner, childCtx)

	return &result, err
}

func (a *Authenticator) Inspect(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.InspectOutput, error) {
	return executeOperation(a, ctx, model.OperationInspect, handler, workflow.Runner.Inspect, opts...)
}

func (a *Authenticator) ListCredentials(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.CredentialsOutput, error) {
	return executeOperation(a, ctx, model.OperationListCredentials, handler, workflow.Runner.ListCredentials, opts...)
}

func (a *Authenticator) CredentialStoreState(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.CredentialStoreStateOutput, error) {
	return executeOperation(
		a,
		ctx,
		model.OperationCredentialStoreState,
		handler,
		workflow.Runner.CredentialStoreState,
		opts...,
	)
}

func (a *Authenticator) DeleteCredential(
	ctx context.Context,
	operation model.DeleteCredentialOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.CredentialDeleteOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.CredentialDeleteOutput, error) {
		return runner.DeleteCredential(ctx, operation)
	}, opts...)
}

func (a *Authenticator) UpdateCredentialUser(
	ctx context.Context,
	operation model.UpdateCredentialUserOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.CredentialUpdateOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.CredentialUpdateOutput, error) {
		return runner.UpdateCredentialUser(ctx, operation)
	}, opts...)
}

func (a *Authenticator) ReadLargeBlob(
	ctx context.Context,
	operation model.ReadLargeBlobOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.LargeBlobReadOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.LargeBlobReadOutput, error) {
		return runner.ReadLargeBlob(ctx, operation)
	}, opts...)
}

func (a *Authenticator) ListLargeBlobs(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.LargeBlobListOutput, error) {
	return executeOperation(a, ctx, model.OperationListLargeBlobs, handler, workflow.Runner.ListLargeBlobs, opts...)
}

func (a *Authenticator) WriteLargeBlob(
	ctx context.Context,
	operation model.WriteLargeBlobOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.LargeBlobMutationOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.LargeBlobMutationOutput, error) {
		return runner.WriteLargeBlob(ctx, operation)
	}, opts...)
}

func (a *Authenticator) DeleteLargeBlob(
	ctx context.Context,
	operation model.DeleteLargeBlobOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.LargeBlobMutationOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.LargeBlobMutationOutput, error) {
		return runner.DeleteLargeBlob(ctx, operation)
	}, opts...)
}

func (a *Authenticator) GarbageCollectLargeBlobs(
	ctx context.Context,
	operation model.GarbageCollectLargeBlobsOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.LargeBlobMutationOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.LargeBlobMutationOutput, error) {
		return runner.GarbageCollectLargeBlobs(ctx, operation)
	}, opts...)
}

func (a *Authenticator) ConfigStatus(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.ConfigStatusOutput, error) {
	return executeOperation(a, ctx, model.OperationConfigStatus, handler, workflow.Runner.ConfigStatus, opts...)
}

func (a *Authenticator) SetPIN(
	ctx context.Context,
	operation model.SetPINOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.PINOutput, error) {
	if operation.NewPIN == "" {
		return nil, normalizeRunError(runtimePINRequiredError("newPIN"), string(operation.Kind()))
	}

	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.PINOutput, error) {
		return runner.SetPIN(ctx, operation)
	}, opts...)
}

func (a *Authenticator) ChangePIN(
	ctx context.Context,
	operation model.ChangePINOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.PINOutput, error) {
	if operation.CurrentPIN == "" {
		return nil, normalizeRunError(runtimePINRequiredError("currentPIN"), string(operation.Kind()))
	}

	if operation.NewPIN == "" {
		return nil, normalizeRunError(runtimePINRequiredError("newPIN"), string(operation.Kind()))
	}

	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.PINOutput, error) {
		return runner.ChangePIN(ctx, operation)
	}, opts...)
}

func (a *Authenticator) SetAlwaysUV(
	ctx context.Context,
	operation model.SetAlwaysUVOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.AuthenticatorConfigOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.AuthenticatorConfigOutput, error) {
		return runner.SetAlwaysUV(ctx, operation)
	}, opts...)
}

func (a *Authenticator) SetMinPINLength(
	ctx context.Context,
	operation model.SetMinPINLengthOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.AuthenticatorConfigOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.AuthenticatorConfigOutput, error) {
		return runner.SetMinPINLength(ctx, operation)
	}, opts...)
}

func (a *Authenticator) EnableLongTouchForReset(
	ctx context.Context,
	operation model.EnableLongTouchForResetOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.AuthenticatorConfigOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.AuthenticatorConfigOutput, error) {
		return runner.EnableLongTouchForReset(ctx, operation)
	}, opts...)
}

func (a *Authenticator) BioSensorInfo(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.BioSensorOutput, error) {
	return executeOperation(a, ctx, model.OperationBioSensorInfo, handler, workflow.Runner.BioSensorInfo, opts...)
}

func (a *Authenticator) BioList(
	ctx context.Context,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.BioListOutput, error) {
	return executeOperation(a, ctx, model.OperationBioList, handler, workflow.Runner.BioList, opts...)
}

func (a *Authenticator) BioEnroll(
	ctx context.Context,
	operation model.BioEnrollOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.BioEnrollOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.BioEnrollOutput, error) {
		return runner.BioEnroll(ctx, operation)
	}, opts...)
}

func (a *Authenticator) BioRename(
	ctx context.Context,
	operation model.BioRenameOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.BioMutationOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.BioMutationOutput, error) {
		return runner.BioRename(ctx, operation)
	}, opts...)
}

func (a *Authenticator) BioRemove(
	ctx context.Context,
	operation model.BioRemoveOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.BioMutationOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.BioMutationOutput, error) {
		return runner.BioRemove(ctx, operation)
	}, opts...)
}

func (a *Authenticator) ResetFactory(
	ctx context.Context,
	operation model.ResetFactoryOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.ResetFactoryOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.ResetFactoryOutput, error) {
		return runner.ResetFactory(ctx, operation)
	}, opts...)
}

func (a *Authenticator) MakeCredential(
	ctx context.Context,
	operation model.MakeCredentialOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.MakeCredentialOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.MakeCredentialOutput, error) {
		return runner.MakeCredential(ctx, operation)
	}, opts...)
}

func (a *Authenticator) GetAssertion(
	ctx context.Context,
	operation model.GetAssertionOperation,
	handler model.InteractionHandler,
	opts ...OperationOption,
) (*model.GetAssertionOutput, error) {
	return executeOperation(a, ctx, operation.Kind(), handler, func(runner workflow.Runner, ctx context.Context) (model.GetAssertionOutput, error) {
		return runner.GetAssertion(ctx, operation)
	}, opts...)
}
