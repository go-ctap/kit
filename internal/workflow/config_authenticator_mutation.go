package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	rtconfig "github.com/go-ctap/kit/internal/config"
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
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildAlwaysUVPreview(status, req.Target, mode)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	if req.DryRun {
		return appconfig.AuthenticatorConfigOutput{Preview: preview}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission:      protocol.PermissionAuthenticatorConfiguration,
		TryWithoutToken: true,
	}, func(token []byte) error {
		return device.ToggleAlwaysUV(ctx, token)
	})
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandToggleAlwaysUv,
		))
	}
	result := rtconfig.AlwaysUVResult(
		r.env.Selected.Attachment.ID,
		req.Target,
		preview.RequestedAlwaysUV,
	)

	return appconfig.AuthenticatorConfigOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func (r Runner) SetMinPINLength(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.SetMinPINLengthOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)
	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildMinPINLengthPreview(status, req, mode)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	if req.DryRun {
		return appconfig.AuthenticatorConfigOutput{Preview: preview}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission:      protocol.PermissionAuthenticatorConfiguration,
		TryWithoutToken: true,
	}, func(token []byte) error {
		return device.SetMinPINLength(ctx, token, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength:     req.NewMinPINLength,
			MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
			ForceChangePIN:      req.ForceChangePIN,
			PINComplexityPolicy: req.PINComplexityPolicy,
		})
	})
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandSetMinPINLength,
		))
	}
	result := rtconfig.MinPINLengthResult(r.env.Selected.Attachment.ID, req)

	return appconfig.AuthenticatorConfigOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
