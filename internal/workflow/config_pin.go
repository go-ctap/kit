package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) SetPIN(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.SetPINOperation,
) (appconfig.PINOutput, error) {
	var output appconfig.PINOutput

	status := appconfig.BuildStatusReport(r.env.Selected, device.GetInfo())

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := appconfig.BuildSetPINPreview(status, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	err = device.SetPIN(ctx, req.NewPIN)
	r.env.Tokens.Invalidate()

	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandSetPIN,
		))
	}

	output.Result = new(appconfig.PINSetResult(r.env.Selected.Fingerprint))
	return output, nil
}

func (r Runner) ChangePIN(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.ChangePINOperation,
) (appconfig.PINOutput, error) {
	var output appconfig.PINOutput

	status := appconfig.BuildStatusReport(r.env.Selected, device.GetInfo())

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := appconfig.BuildChangePINPreview(status, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	err = device.ChangePIN(ctx, req.CurrentPIN, req.NewPIN)
	r.env.Tokens.Invalidate()

	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandChangePIN,
		))
	}

	output.Result = new(appconfig.PINChangeResult(r.env.Selected.Fingerprint))
	return output, nil
}
