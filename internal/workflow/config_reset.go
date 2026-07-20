package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	rtconfig "github.com/go-ctap/kit/internal/config"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
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

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return output, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)
	preview := rtconfig.BuildResetFactoryPreview(status)

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

	r.recordStateEffect(rtruntime.StateEffectAuthenticatorReset)

	err = device.Reset(ctx)
	r.env.Tokens.Invalidate()

	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorReset,
		))
	}
	output.Result = new(rtconfig.ResetResultForDevice(r.env.Selected.Fingerprint))
	return output, nil
}
