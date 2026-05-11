package workflow

import (
	"context"

	"github.com/go-ctap/kit/model"
	"github.com/samber/lo"
)

type confirmationRequest struct {
	confirmed       bool
	message         string
	fallbackMessage string
	destructive     bool
	declinedErr     error
	preview         any
}

func (r Runner) confirmMutation(ctx context.Context, req confirmationRequest) error {
	if req.confirmed {
		return nil
	}

	response, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindConfirm,
		Message:     lo.CoalesceOrEmpty(req.message, req.fallbackMessage),
		Destructive: req.destructive,
		Preview:     req.preview,
	})
	if err != nil {
		return err
	}

	if !response.Confirmed {
		return req.declinedErr
	}

	return nil
}
