package runtime

import (
	"context"

	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

type InteractionBroker struct {
	events  model.EventSink
	handler model.InteractionHandler
}

func NewInteractionBroker(events model.EventSink, handler model.InteractionHandler) *InteractionBroker {
	if events == nil {
		events = model.NoopEventSink{}
	}

	return &InteractionBroker{
		events:  events,
		handler: handler,
	}
}

func (b *InteractionBroker) RequestInteraction(
	ctx context.Context,
	req model.InteractionRequest,
) (model.InteractionResponse, error) {
	if req.Kind == "" {
		return model.InteractionResponse{}, failure.New(failure.CodeInteractionKindRequired,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	b.events.Emit(ctx, model.OperationEvent{
		Stage:   model.OperationStageInteractionRequired,
		Kind:    req.Kind,
		Message: req.Message,
	})

	if b.handler == nil {
		return model.InteractionResponse{}, failure.New(failure.CodeInteractionHandlerRequired,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	response, err := b.handler.RequestInteraction(ctx, req)
	if err != nil {
		secret.Zero(response.PIN)

		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}

		return model.InteractionResponse{}, annotateInteractionError(err)
	}

	if err := validateInteractionResponse(req, response); err != nil {
		secret.Zero(response.PIN)

		return model.InteractionResponse{}, err
	}

	if err := ctx.Err(); err != nil {
		secret.Zero(response.PIN)

		return model.InteractionResponse{}, annotateInteractionError(err)
	}

	return response, nil
}

func validateInteractionResponse(req model.InteractionRequest, response model.InteractionResponse) error {
	if response.Canceled {
		return failure.New(failure.CodeInteractionCanceled,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	if req.Kind == model.InteractionKindPIN && len(response.PIN) == 0 {
		return failure.New(failure.CodePINRequired,
			failure.WithPhase(failure.PhaseInteraction),
			failure.WithParams(map[string]string{"field": "pin"}),
		)
	}

	return nil
}

func annotateInteractionError(err error) error {
	return errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseInteraction))
}
