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
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.ResetFactoryOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)
	preview := rtconfig.BuildResetFactoryPreview(status)

	if req.DryRun {
		preview.Mode = safety.PreviewModeDryRun

		return appconfig.ResetFactoryOutput{Preview: preview}, nil
	}

	if _, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator " + string(r.env.Selected.Attachment.ID) + " to factory reset.",
		Destructive: true,
		Preview:     preview,
	}); err != nil {
		return appconfig.ResetFactoryOutput{}, err
	}

	r.recordStateEffect(rtruntime.StateEffectAuthenticatorReset)

	err = device.Reset(ctx)
	r.env.Tokens.Invalidate()

	if err != nil {
		return appconfig.ResetFactoryOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorReset,
		))
	}
	result := rtconfig.ResetResultForDevice(r.env.Selected.Attachment.ID)

	return appconfig.ResetFactoryOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
