package workflow

import (
	"context"

	"github.com/go-ctap/kit/internal/authenticator"
	rtinspect "github.com/go-ctap/kit/internal/inspect"
	appinspect "github.com/go-ctap/kit/model/inspect"
)

func (r Runner) Inspect(ctx context.Context, device authenticator.InfoProvider) (appinspect.Result, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appinspect.Result{}, err
	}

	return rtinspect.BuildResult(r.env.Selected, info), nil
}
