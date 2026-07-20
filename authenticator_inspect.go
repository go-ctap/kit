package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/workflow"
	"github.com/go-ctap/kit/model/inspect"
	appoperation "github.com/go-ctap/kit/model/operation"
)

func (a *Authenticator) Inspect(ctx context.Context, opts ...OperationOption) (*inspect.Result, error) {
	return executeOperation(a, ctx, appoperation.Inspect, func(runner workflow.Runner, ctx context.Context) (inspect.Result, error) {
		return runner.Inspect(ctx, a.info)
	}, opts...)
}
