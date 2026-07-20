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

func (r Runner) BioRename(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioRenameOperation,
) (appconfig.BioMutationOutput, error) {
	var output appconfig.BioMutationOutput

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return output, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioRenamePreview(status, req.TemplateIDHex, req.FriendlyName, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	templateID, err := rtconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return output, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return device.SetFriendlyName(ctx, token, templateID, req.FriendlyName)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandSetFriendlyName,
		))
	}

	result := appconfig.BioMutationResult{
		Operation:         appconfig.BioMutationRename,
		DeviceFingerprint: r.env.Selected.Fingerprint,
		PreviewOnly:       preview.PreviewOnly,
		TemplateIDHex:     req.TemplateIDHex,
		FriendlyName:      req.FriendlyName,
	}

	output.Result = &result
	return output, nil
}

func (r Runner) BioRemove(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioRemoveOperation,
) (appconfig.BioMutationOutput, error) {
	var output appconfig.BioMutationOutput

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return output, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioRemovePreview(status, req.TemplateIDHex, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	templateID, err := rtconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return output, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return device.RemoveEnrollment(ctx, token, templateID)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandRemoveEnrollment,
		))
	}
	result := appconfig.BioMutationResult{
		Operation:         appconfig.BioMutationRemove,
		DeviceFingerprint: r.env.Selected.Fingerprint,
		PreviewOnly:       preview.PreviewOnly,
		TemplateIDHex:     req.TemplateIDHex,
	}

	output.Result = &result
	return output, nil
}
