package workflow

import (
	"context"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) setPIN(ctx context.Context, req model.SetPINOperation) (model.OperationResult, error) {
	var output model.PINOutput

	status := r.statusReport()

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
		fallbackMessage: "Set PIN on authenticator " + r.env.Selected.DeviceID + "?",
		destructive:     false,
		declinedErr:     appconfig.ErrConfirmationRequired,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.configManager().SetPIN(req.NewPIN)
	if err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithClientPINSubCommand(
			model.OperationSetPIN,
			ctaptypes.ClientPINSubCommandSetPIN,
		))
	}

	output.Result = new(appconfig.PINSetResult(r.env.Selected.DeviceID))
	return output, nil
}

func (r Runner) changePIN(ctx context.Context, req model.ChangePINOperation) (model.OperationResult, error) {
	var output model.PINOutput

	status := r.statusReport()

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
		fallbackMessage: "Change PIN on authenticator " + r.env.Selected.DeviceID + "?",
		destructive:     false,
		declinedErr:     appconfig.ErrConfirmationRequired,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.configManager().ChangePIN(req.CurrentPIN, req.NewPIN)
	if err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithClientPINSubCommand(
			model.OperationChangePIN,
			ctaptypes.ClientPINSubCommandChangePIN,
		))
	}

	output.Result = new(appconfig.PINChangeResult(r.env.Selected.DeviceID))
	return output, nil
}
