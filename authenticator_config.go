package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model/config"
	appoperation "github.com/go-ctap/kit/model/operation"
)

func (a *Authenticator) ConfigStatus(ctx context.Context, opts ...OperationOption) (*config.StatusReport, error) {
	return executeOperation(a, ctx, appoperation.ConfigStatus, func(runner workflow.Runner, ctx context.Context) (config.StatusReport, error) {
		return runner.ConfigStatus(ctx, a.configStatus)
	}, opts...)
}

func (a *Authenticator) SetPIN(
	ctx context.Context,
	operation config.SetPINOperation,
	opts ...OperationOption,
) (*config.PINOutput, error) {
	if operation.NewPIN == "" {
		return nil, normalizeRunError(runtimePINRequiredError("newPIN"), string(appoperation.SetPIN))
	}

	return executeOperation(a, ctx, appoperation.SetPIN, func(runner workflow.Runner, ctx context.Context) (config.PINOutput, error) {
		return runner.SetPIN(ctx, a.config, operation)
	}, opts...)
}

func (a *Authenticator) ChangePIN(
	ctx context.Context,
	operation config.ChangePINOperation,
	opts ...OperationOption,
) (*config.PINOutput, error) {
	if operation.CurrentPIN == "" {
		return nil, normalizeRunError(runtimePINRequiredError("currentPIN"), string(appoperation.ChangePIN))
	}

	if operation.NewPIN == "" {
		return nil, normalizeRunError(runtimePINRequiredError("newPIN"), string(appoperation.ChangePIN))
	}

	return executeOperation(a, ctx, appoperation.ChangePIN, func(runner workflow.Runner, ctx context.Context) (config.PINOutput, error) {
		return runner.ChangePIN(ctx, a.config, operation)
	}, opts...)
}

func (a *Authenticator) SetAlwaysUV(
	ctx context.Context,
	operation config.SetAlwaysUVOperation,
	opts ...OperationOption,
) (*config.AuthenticatorConfigOutput, error) {
	return executeOperation(a, ctx, appoperation.SetAlwaysUV, func(runner workflow.Runner, ctx context.Context) (config.AuthenticatorConfigOutput, error) {
		return runner.SetAlwaysUV(ctx, a.config, operation)
	}, opts...)
}

func (a *Authenticator) SetMinPINLength(
	ctx context.Context,
	operation config.SetMinPINLengthOperation,
	opts ...OperationOption,
) (*config.AuthenticatorConfigOutput, error) {
	return executeOperation(a, ctx, appoperation.SetMinPINLength, func(runner workflow.Runner, ctx context.Context) (config.AuthenticatorConfigOutput, error) {
		return runner.SetMinPINLength(ctx, a.config, operation)
	}, opts...)
}

func (a *Authenticator) EnableLongTouchForReset(
	ctx context.Context,
	operation config.EnableLongTouchForResetOperation,
	opts ...OperationOption,
) (*config.AuthenticatorConfigOutput, error) {
	return executeOperation(a, ctx, appoperation.EnableLongTouchForReset, func(runner workflow.Runner, ctx context.Context) (config.AuthenticatorConfigOutput, error) {
		return runner.EnableLongTouchForReset(ctx, a.config, operation)
	}, opts...)
}

func (a *Authenticator) BioSensorInfo(ctx context.Context, opts ...OperationOption) (*config.BioSensorReport, error) {
	return executeOperation(a, ctx, appoperation.BioSensorInfo, func(runner workflow.Runner, ctx context.Context) (config.BioSensorReport, error) {
		return runner.BioSensorInfo(ctx, a.bio)
	}, opts...)
}

func (a *Authenticator) BioList(ctx context.Context, opts ...OperationOption) (*config.BioListReport, error) {
	return executeOperation(a, ctx, appoperation.BioList, func(runner workflow.Runner, ctx context.Context) (config.BioListReport, error) {
		return runner.BioList(ctx, a.bio)
	}, opts...)
}

func (a *Authenticator) BioEnroll(
	ctx context.Context,
	operation config.BioEnrollOperation,
	opts ...OperationOption,
) (*config.BioEnrollOutput, error) {
	return executeOperation(a, ctx, appoperation.BioEnroll, func(runner workflow.Runner, ctx context.Context) (config.BioEnrollOutput, error) {
		return runner.BioEnroll(ctx, a.bio, operation)
	}, opts...)
}

func (a *Authenticator) BioRename(
	ctx context.Context,
	operation config.BioRenameOperation,
	opts ...OperationOption,
) (*config.BioMutationOutput, error) {
	return executeOperation(a, ctx, appoperation.BioRename, func(runner workflow.Runner, ctx context.Context) (config.BioMutationOutput, error) {
		return runner.BioRename(ctx, a.bio, operation)
	}, opts...)
}

func (a *Authenticator) BioRemove(
	ctx context.Context,
	operation config.BioRemoveOperation,
	opts ...OperationOption,
) (*config.BioMutationOutput, error) {
	return executeOperation(a, ctx, appoperation.BioRemove, func(runner workflow.Runner, ctx context.Context) (config.BioMutationOutput, error) {
		return runner.BioRemove(ctx, a.bio, operation)
	}, opts...)
}

func (a *Authenticator) ResetFactory(
	ctx context.Context,
	operation config.ResetFactoryOperation,
	opts ...OperationOption,
) (*config.ResetFactoryOutput, error) {
	return executeOperation(a, ctx, appoperation.ResetFactory, func(runner workflow.Runner, ctx context.Context) (config.ResetFactoryOutput, error) {
		return runner.ResetFactory(ctx, a.config, operation)
	}, opts...)
}
