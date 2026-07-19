package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) renameBio(ctx context.Context, req model.BioRenameOperation) (model.OperationResult, error) {
	var output model.BioMutationOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := appconfig.BuildBioRenamePreview(status, req.TemplateIDHex, req.FriendlyName, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	templateID, err := appconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return output, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return r.env.Authenticator.SetFriendlyName(ctx, token, templateID, req.FriendlyName)
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

func (r Runner) removeBio(ctx context.Context, req model.BioRemoveOperation) (model.OperationResult, error) {
	var output model.BioMutationOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := appconfig.BuildBioRemovePreview(status, req.TemplateIDHex, mode)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	templateID, err := appconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return output, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return r.env.Authenticator.RemoveEnrollment(ctx, token, templateID)
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
