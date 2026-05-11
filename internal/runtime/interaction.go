package runtime

import (
	"context"
	"errors"
	"slices"

	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
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
		return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorInvalidState, "interaction kind is required", nil)
	}

	b.events.Emit(model.OperationEvent{
		Stage:   model.OperationStageInteractionRequired,
		Kind:    req.Kind,
		Message: req.Message,
	})

	if b.handler == nil {
		return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorInvalidState, "interaction handler is required", nil)
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
		return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorCanceled, "interaction context canceled", err)
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

			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorCanceled, "interaction context canceled", err)
			}

			return model.InteractionResponse{}, err
		}

		if err := ctx.Err(); err != nil {
			secret.Zero(response.PIN)

			return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorCanceled, "interaction context canceled", err)
		}

		return response, nil
	case <-ctx.Done():
		return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorCanceled, "interaction context canceled", ctx.Err())
	}
}

func validateInteractionResponse(req model.InteractionRequest, response model.InteractionResponse) error {
	if response.Canceled {
		return model.NewRuntimeError(model.ErrorCanceled, "interaction canceled", nil)
	}

	if req.Kind == model.InteractionKindPIN && len(response.PIN) == 0 {
		return model.NewRuntimeError(model.ErrorInvalidOperation, "PIN is required", appconfig.ErrPINRequired)
	}

	return nil
}
