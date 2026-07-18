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

func (r Runner) resetFactory(ctx context.Context, req model.ResetFactoryOperation) (model.OperationResult, error) {
	var output model.ResetFactoryOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())
	preview := appconfig.BuildResetFactoryPreview(status)

	output.Preview = preview
	if req.DryRun {
		preview.Mode = safety.PreviewModeDryRun
		output.Preview = preview

		return output, nil
	}

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Factory reset authenticator " + preview.Device.Fingerprint + "?",
		destructive:     true,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	if _, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator " + r.env.Selected.Fingerprint + " to factory reset.",
		Destructive: true,
		Preview:     preview,
	}); err != nil {
		return output, err
	}

	err := r.env.Authenticator.Reset(ctx)
	r.env.Tokens.Invalidate()
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorReset,
		))
	}

	output.Result = new(appconfig.ResetResultForDevice(r.env.Selected.Fingerprint))
	return output, nil
}
