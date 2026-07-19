package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model/credentials"
	appoperation "github.com/go-ctap/kit/model/operation"
)

func (a *Authenticator) ListCredentials(ctx context.Context, opts ...OperationOption) (*credentials.InventoryReport, error) {
	return executeOperation(a, ctx, appoperation.ListCredentials, func(runner workflow.Runner, ctx context.Context) (credentials.InventoryReport, error) {
		return runner.ListCredentials(ctx, a.device)
	}, opts...)
}

func (a *Authenticator) CredentialStoreState(ctx context.Context, opts ...OperationOption) (*credentials.StoreStateResult, error) {
	return executeOperation(a, ctx, appoperation.CredentialStoreState, func(runner workflow.Runner, ctx context.Context) (credentials.StoreStateResult, error) {
		return runner.CredentialStoreState(ctx, a.device)
	}, opts...)
}

func (a *Authenticator) DeleteCredential(
	ctx context.Context,
	operation credentials.DeleteOperation,
	opts ...OperationOption,
) (*credentials.DeleteOutput, error) {
	return executeOperation(a, ctx, appoperation.DeleteCredential, func(runner workflow.Runner, ctx context.Context) (credentials.DeleteOutput, error) {
		return runner.DeleteCredential(ctx, a.device, operation)
	}, opts...)
}

func (a *Authenticator) UpdateCredentialUser(
	ctx context.Context,
	operation credentials.UpdateUserOperation,
	opts ...OperationOption,
) (*credentials.UpdateUserOutput, error) {
	return executeOperation(a, ctx, appoperation.UpdateCredentialUser, func(runner workflow.Runner, ctx context.Context) (credentials.UpdateUserOutput, error) {
		return runner.UpdateCredentialUser(ctx, a.device, operation)
	}, opts...)
}
