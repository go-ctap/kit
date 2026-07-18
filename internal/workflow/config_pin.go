package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) setPIN(ctx context.Context, req model.SetPINOperation) (model.OperationResult, error) {
	var output model.PINOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())

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

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Set PIN on authenticator " + r.env.Selected.Fingerprint + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.env.Authenticator.SetPIN(ctx, req.NewPIN)
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

func (r Runner) changePIN(ctx context.Context, req model.ChangePINOperation) (model.OperationResult, error) {
	var output model.PINOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())

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

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Change PIN on authenticator " + r.env.Selected.Fingerprint + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.env.Authenticator.ChangePIN(ctx, req.CurrentPIN, req.NewPIN)
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
