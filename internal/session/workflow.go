package session

import (
	"context"

	"github.com/go-ctap/kit/model"
)

func (c *Core) RunSerializedWorkflow(
	ctx context.Context,
	operation func(context.Context) (model.OperationResult, error),
) (model.OperationResult, error) {
	c.workflowMu.Lock()
	defer c.workflowMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := c.trackActiveOperation(cancel); err != nil {
		return nil, err
	}
	defer c.clearActiveOperation()

	return operation(childCtx)
}
