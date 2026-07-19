package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) EnableLongTouchForReset(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.EnableLongTouchForResetOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	var output appconfig.AuthenticatorConfigOutput

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := appconfig.BuildEnableLongTouchForResetPreview(appconfig.BuildStatusReport(r.env.Selected, device.GetInfo()), mode)
	if err != nil {
		return output, err
	}
	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionAuthenticatorConfiguration,
		Optional:   true,
	}, func(token []byte) error {
		return device.EnableLongTouchForReset(ctx, token)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandEnableLongTouchForReset,
		))
	}

	output.Result = new(appconfig.LongTouchForResetResult(r.env.Selected.Fingerprint))

	return output, nil
}
