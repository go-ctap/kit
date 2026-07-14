package runtime

import (
	"context"
	"slices"

	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/samber/mo"
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

	b.events.Emit(model.OperationEvent{
		Stage:   model.OperationStageInteractionRequired,
		Kind:    req.Kind,
		Message: req.Message,
	})

	if b.handler == nil {
		return model.InteractionResponse{}, failure.New(failure.CodeInteractionHandlerRequired,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	response, err := callInteractionHandler(ctx, b.handler, req)
	if err != nil {
		return model.InteractionResponse{}, err
	}

	if err := validateInteractionResponse(req, response); err != nil {
		secret.Zero(response.PIN)

		return model.InteractionResponse{}, err
	}

	return response, nil
}

func callInteractionHandler(
	ctx context.Context,
	handler model.InteractionHandler,
	req model.InteractionRequest,
) (model.InteractionResponse, error) {
	if err := ctx.Err(); err != nil {
		return model.InteractionResponse{}, annotateInteractionError(err)
	}

	result := make(chan mo.Either[model.InteractionResponse, error])

	go func() {
		response, err := handler.RequestInteraction(req)

		if len(response.PIN) != 0 {
			pin := slices.Clone(response.PIN)
			secret.Zero(response.PIN)
			response.PIN = pin
		}

		resolution := mo.Left[model.InteractionResponse, error](response)
		if err != nil {
			secret.Zero(response.PIN)

			resolution = mo.Right[model.InteractionResponse, error](err)
		}

		select {
		case result <- resolution:
		case <-ctx.Done():
			secret.Zero(response.PIN)
		}
	}()

	select {
	case resolution := <-result:
		response, err := resolution.Unpack()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}

			return model.InteractionResponse{}, annotateInteractionError(err)
		}

		if err := ctx.Err(); err != nil {
			secret.Zero(response.PIN)

			return model.InteractionResponse{}, annotateInteractionError(err)
		}

		return response, nil
	case <-ctx.Done():
		return model.InteractionResponse{}, annotateInteractionError(ctx.Err())
	}
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
