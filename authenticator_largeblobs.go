package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/largeblobs"
)

func (a *Authenticator) ReadLargeBlob(
	ctx context.Context,
	operation largeblobs.ReadOperation,
	opts ...OperationOption,
) (*largeblobs.ReadReport, error) {
	return executeOperation(a, ctx, model.OperationReadLargeBlob, func(runner workflow.Runner, ctx context.Context) (largeblobs.ReadReport, error) {
		return runner.ReadLargeBlob(ctx, a.device, operation)
	}, opts...)
}

func (a *Authenticator) ListLargeBlobs(ctx context.Context, opts ...OperationOption) (*largeblobs.ListReport, error) {
	return executeOperation(a, ctx, model.OperationListLargeBlobs, func(runner workflow.Runner, ctx context.Context) (largeblobs.ListReport, error) {
		return runner.ListLargeBlobs(ctx, a.device)
	}, opts...)
}

func (a *Authenticator) WriteLargeBlob(
	ctx context.Context,
	operation largeblobs.WriteOperation,
	opts ...OperationOption,
) (*largeblobs.MutationOutput, error) {
	return executeOperation(a, ctx, model.OperationWriteLargeBlob, func(runner workflow.Runner, ctx context.Context) (largeblobs.MutationOutput, error) {
		return runner.WriteLargeBlob(ctx, a.device, operation)
	}, opts...)
}

func (a *Authenticator) DeleteLargeBlob(
	ctx context.Context,
	operation largeblobs.DeleteOperation,
	opts ...OperationOption,
) (*largeblobs.MutationOutput, error) {
	return executeOperation(a, ctx, model.OperationDeleteLargeBlob, func(runner workflow.Runner, ctx context.Context) (largeblobs.MutationOutput, error) {
		return runner.DeleteLargeBlob(ctx, a.device, operation)
	}, opts...)
}

func (a *Authenticator) GarbageCollectLargeBlobs(
	ctx context.Context,
	operation largeblobs.GarbageCollectOperation,
	opts ...OperationOption,
) (*largeblobs.MutationOutput, error) {
	return executeOperation(a, ctx, model.OperationGarbageCollectLargeBlobs, func(runner workflow.Runner, ctx context.Context) (largeblobs.MutationOutput, error) {
		return runner.GarbageCollectLargeBlobs(ctx, a.device, operation)
	}, opts...)
}
