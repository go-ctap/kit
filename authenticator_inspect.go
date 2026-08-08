package ctapkit

import (
	"context"

	"github.com/telesma-app/kit/internal/workflow"
	"github.com/telesma-app/kit/model/inspect"
	appoperation "github.com/telesma-app/kit/model/operation"
)

func (a *Authenticator) Inspect(ctx context.Context, opts ...OperationOption) (inspect.Result, error) {
	return executeOperation(a, ctx, appoperation.Inspect, func(runner workflow.Runner, ctx context.Context) (inspect.Result, error) {
		return runner.Inspect(ctx, a.info)
	}, opts...)
}
