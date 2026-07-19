package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/inspect"
)

func (a *Authenticator) Inspect(ctx context.Context, opts ...OperationOption) (*inspect.Result, error) {
	return executeOperation(a, ctx, model.OperationInspect, func(runner workflow.Runner, ctx context.Context) (inspect.Result, error) {
		return runner.Inspect(ctx, a.device)
	}, opts...)
}
