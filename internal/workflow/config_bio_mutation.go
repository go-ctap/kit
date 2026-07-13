package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) renameBio(ctx context.Context, req model.BioRenameOperation) (model.OperationResult, error) {
	var output model.BioMutationOutput

	status := r.statusReport()

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

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Rename biometric enrollment " + req.TemplateIDHex + "?",
		destructive:     false,
		declinedErr:     appconfig.ErrConfirmationRequired,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	templateID, err := appconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionBioEnrollment, "")
	if err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithBioEnrollmentSubCommand(
			model.OperationBioRename,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandSetFriendlyName,
		))
	}
	defer secret.Zero(token)

	if err := r.bioEnrollmentManager().SetFriendlyName(ctx, token, templateID, req.FriendlyName); err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithBioEnrollmentSubCommand(
			model.OperationBioRename,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandSetFriendlyName,
		))
	}

	result := appconfig.BioMutationResult{
		Operation:     appconfig.BioMutationRename,
		DeviceID:      r.env.Selected.DeviceID,
		PreviewOnly:   preview.PreviewOnly,
		TemplateIDHex: req.TemplateIDHex,
		FriendlyName:  req.FriendlyName,
	}

	output.Result = &result
	return output, nil
}

func (r Runner) removeBio(ctx context.Context, req model.BioRemoveOperation) (model.OperationResult, error) {
	var output model.BioMutationOutput

	status := r.statusReport()

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

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Remove biometric enrollment " + req.TemplateIDHex + "?",
		destructive:     true,
		declinedErr:     appconfig.ErrConfirmationRequired,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	templateID, err := appconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionBioEnrollment, "")
	if err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithBioEnrollmentSubCommand(
			model.OperationBioRemove,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandRemoveEnrollment,
		))
	}
	defer secret.Zero(token)

	if err := r.bioEnrollmentManager().RemoveEnrollment(ctx, token, templateID); err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithBioEnrollmentSubCommand(
			model.OperationBioRemove,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandRemoveEnrollment,
		))
	}

	result := appconfig.BioMutationResult{
		Operation:     appconfig.BioMutationRemove,
		DeviceID:      r.env.Selected.DeviceID,
		PreviewOnly:   preview.PreviewOnly,
		TemplateIDHex: req.TemplateIDHex,
	}

	output.Result = &result
	return output, nil
}
