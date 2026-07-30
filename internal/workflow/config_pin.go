package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	rtconfig "github.com/go-ctap/kit/internal/config"
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
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.PINOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildSetPINPreview(status, mode)
	if err != nil {
		return appconfig.PINOutput{}, err
	}

	if req.DryRun {
		return appconfig.PINOutput{Preview: preview}, nil
	}

	err = device.SetPIN(ctx, req.NewPIN)
	r.env.Tokens.Invalidate()

	if err != nil {
		return appconfig.PINOutput{}, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandSetPIN,
		))
	}
	result := rtconfig.PINSetResult(r.env.Selected.Attachment.ID)

	return appconfig.PINOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func (r Runner) ChangePIN(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.ChangePINOperation,
) (appconfig.PINOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.PINOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildChangePINPreview(status, mode)
	if err != nil {
		return appconfig.PINOutput{}, err
	}

	if req.DryRun {
		return appconfig.PINOutput{Preview: preview}, nil
	}

	err = device.ChangePIN(ctx, req.CurrentPIN, req.NewPIN)
	r.env.Tokens.Invalidate()

	if err != nil {
		return appconfig.PINOutput{}, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandChangePIN,
		))
	}
	result := rtconfig.PINChangeResult(r.env.Selected.Attachment.ID)

	return appconfig.PINOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
