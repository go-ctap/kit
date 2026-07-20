package workflow

import (
	"context"

	"github.com/go-ctap/kit/internal/authenticator"
	rtinspect "github.com/go-ctap/kit/internal/inspect"
	"github.com/go-ctap/kit/internal/vendorinfo"
	appinspect "github.com/go-ctap/kit/model/inspect"
)

func (r Runner) Inspect(ctx context.Context, device authenticator.InfoProvider) (appinspect.Result, error) {
	selected := r.env.Selected
	metadata, _ := vendorinfo.EnrichOpen(ctx, selected, device)
	if metadata != nil {
		selected.Metadata = metadata
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appinspect.Result{}, err
	}

	return rtinspect.BuildResult(selected, info), nil
}
