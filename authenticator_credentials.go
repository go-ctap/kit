package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/credentials"
)

func (a *Authenticator) ListCredentials(ctx context.Context, opts ...OperationOption) (*credentials.InventoryReport, error) {
	return executeOperation(a, ctx, model.OperationListCredentials, func(runner workflow.Runner, ctx context.Context) (credentials.InventoryReport, error) {
		return runner.ListCredentials(ctx, a.device)
	}, opts...)
}

func (a *Authenticator) CredentialStoreState(ctx context.Context, opts ...OperationOption) (*credentials.StoreStateResult, error) {
	return executeOperation(a, ctx, model.OperationCredentialStoreState, func(runner workflow.Runner, ctx context.Context) (credentials.StoreStateResult, error) {
		return runner.CredentialStoreState(ctx, a.device)
	}, opts...)
}

func (a *Authenticator) DeleteCredential(
	ctx context.Context,
	operation credentials.DeleteOperation,
	opts ...OperationOption,
) (*credentials.DeleteOutput, error) {
	return executeOperation(a, ctx, model.OperationDeleteCredential, func(runner workflow.Runner, ctx context.Context) (credentials.DeleteOutput, error) {
		return runner.DeleteCredential(ctx, a.device, operation)
	}, opts...)
}

func (a *Authenticator) UpdateCredentialUser(
	ctx context.Context,
	operation credentials.UpdateUserOperation,
	opts ...OperationOption,
) (*credentials.UpdateUserOutput, error) {
	return executeOperation(a, ctx, model.OperationUpdateCredentialUser, func(runner workflow.Runner, ctx context.Context) (credentials.UpdateUserOutput, error) {
		return runner.UpdateCredentialUser(ctx, a.device, operation)
	}, opts...)
}
