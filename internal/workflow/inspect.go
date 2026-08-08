package workflow

import (
	"context"

	"github.com/telesma-app/kit/internal/authenticator"
	rtinspect "github.com/telesma-app/kit/internal/inspect"
	appinspect "github.com/telesma-app/kit/model/inspect"
)

func (r Runner) Inspect(ctx context.Context, device authenticator.InfoProvider) (appinspect.Result, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appinspect.Result{}, err
	}

	return rtinspect.BuildResult(r.env.Selected, info), nil
}
