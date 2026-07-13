package workflow

import (
	"context"

	"github.com/go-ctap/kit/internal/vendorinfo"
	"github.com/go-ctap/kit/model"
)

func (r Runner) inspect(ctx context.Context) (model.InspectResult, error) {
	selected := r.env.Selected
	metadata, _ := vendorinfo.EnrichOpen(ctx, selected, r.env.Authenticator)
	if metadata != nil {
		selected.Metadata = metadata
	}

	return model.NewInspectResult(selected, r.infoProvider().GetInfo()), nil
}
