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

func (r Runner) ResetFactory(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.ResetFactoryOperation,
) (appconfig.ResetFactoryOutput, error) {
	var output appconfig.ResetFactoryOutput

	status := appconfig.BuildStatusReport(r.env.Selected, device.GetInfo())
	preview := appconfig.BuildResetFactoryPreview(status)

	output.Preview = preview

	if req.DryRun {
		preview.Mode = safety.PreviewModeDryRun
		output.Preview = preview

		return output, nil
	}

	if _, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator " + r.env.Selected.Fingerprint + " to factory reset.",
		Destructive: true,
		Preview:     preview,
	}); err != nil {
		return output, err
	}

	err := device.Reset(ctx)
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
