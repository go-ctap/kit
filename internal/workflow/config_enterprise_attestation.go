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

func (r Runner) EnableEnterpriseAttestation(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.EnableEnterpriseAttestationOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}
	preview, err := rtconfig.BuildEnableEnterpriseAttestationPreview(rtconfig.BuildStatusReport(r.env.Selected, info), mode)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	if req.DryRun {
		return appconfig.AuthenticatorConfigOutput{Preview: preview}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionAuthenticatorConfiguration,
		Optional:   true,
	}, func(token []byte) error {
		return device.EnableEnterpriseAttestation(ctx, token)
	})
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandEnableEnterpriseAttestation,
		))
	}
	result := rtconfig.EnterpriseAttestationResult(r.env.Selected.Attachment.ID)

	return appconfig.AuthenticatorConfigOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
