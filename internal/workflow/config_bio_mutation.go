package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func (r Runner) BioRename(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioRenameOperation,
) (appconfig.BioMutationOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioRenamePreview(status, req.TemplateIDHex, req.FriendlyName, mode)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}

	if req.DryRun {
		return appconfig.BioMutationOutput{Preview: preview}, nil
	}

	templateID, err := rtconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return device.SetFriendlyName(ctx, token, templateID, req.FriendlyName)
	})
	if err != nil {
		return appconfig.BioMutationOutput{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandSetFriendlyName,
		))
	}

	result := appconfig.BioMutationResult{
		Operation:     appconfig.BioMutationRename,
		AttachmentID:  r.env.Selected.Attachment.ID,
		PreviewOnly:   preview.PreviewOnly,
		TemplateIDHex: req.TemplateIDHex,
		FriendlyName:  req.FriendlyName,
	}

	return appconfig.BioMutationOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func (r Runner) BioRemove(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioRemoveOperation,
) (appconfig.BioMutationOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioRemovePreview(status, req.TemplateIDHex, mode)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}

	if req.DryRun {
		return appconfig.BioMutationOutput{Preview: preview}, nil
	}

	templateID, err := rtconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return device.RemoveEnrollment(ctx, token, templateID)
	})
	if err != nil {
		return appconfig.BioMutationOutput{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandRemoveEnrollment,
		))
	}
	result := appconfig.BioMutationResult{
		Operation:     appconfig.BioMutationRemove,
		AttachmentID:  r.env.Selected.Attachment.ID,
		PreviewOnly:   preview.PreviewOnly,
		TemplateIDHex: req.TemplateIDHex,
	}

	return appconfig.BioMutationOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
