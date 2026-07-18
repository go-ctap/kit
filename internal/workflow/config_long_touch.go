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

func (r Runner) enableLongTouchForReset(ctx context.Context, req model.EnableLongTouchForResetOperation) (model.OperationResult, error) {
	var output model.AuthenticatorConfigOutput

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}
	preview, err := appconfig.BuildEnableLongTouchForResetPreview(appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo()), mode)
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
		fallbackMessage: "Enable long touch for reset on authenticator " + r.env.Selected.Fingerprint + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.runWithOptionalToken(ctx, protocol.PermissionAuthenticatorConfiguration, "", func(token []byte) error {
		return r.env.Authenticator.EnableLongTouchForReset(ctx, token)
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
