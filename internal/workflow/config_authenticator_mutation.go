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

func (r Runner) SetAlwaysUV(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.SetAlwaysUVOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	var output appconfig.AuthenticatorConfigOutput

	status := appconfig.BuildStatusReport(r.env.Selected, device.GetInfo())

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := appconfig.BuildAlwaysUVPreview(status, req.Target, mode)
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
		return device.ToggleAlwaysUV(ctx, token)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandToggleAlwaysUv,
		))
	}

	output.Result = new(appconfig.AlwaysUVResult(
		r.env.Selected.Fingerprint,
		req.Target,
		preview.RequestedAlwaysUV,
	))
	return output, nil
}

func (r Runner) SetMinPINLength(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.SetMinPINLengthOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	var output appconfig.AuthenticatorConfigOutput

	status := appconfig.BuildStatusReport(r.env.Selected, device.GetInfo())
	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := appconfig.BuildMinPINLengthPreview(status, req, mode)
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
		return device.SetMinPINLength(ctx, token, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength:     req.NewMinPINLength,
			MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
			ForceChangePIN:      req.ForceChangePIN,
			PINComplexityPolicy: req.PINComplexityPolicy,
		})
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandSetMinPINLength,
		))
	}

	output.Result = new(appconfig.MinPINLengthResult(r.env.Selected.Fingerprint, req))
	return output, nil
}
