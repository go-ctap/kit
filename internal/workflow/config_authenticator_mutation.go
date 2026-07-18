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

func (r Runner) setAlwaysUV(ctx context.Context, req model.SetAlwaysUVOperation) (model.OperationResult, error) {
	var output model.AuthenticatorConfigOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())

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

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Set alwaysUv " + string(req.Target) + " on authenticator " + r.env.Selected.Fingerprint + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.runWithOptionalToken(ctx, protocol.PermissionAuthenticatorConfiguration, "", func(token []byte) error {
		return r.env.Authenticator.ToggleAlwaysUV(ctx, token)
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

func (r Runner) setMinPINLength(ctx context.Context, req model.SetMinPINLengthOperation) (model.OperationResult, error) {
	var output model.AuthenticatorConfigOutput

	status := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())
	minReq := appconfig.MinPINLengthRequest{
		NewMinPINLength:     req.NewMinPINLength,
		MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
		ForceChangePIN:      req.ForceChangePIN,
		PINComplexityPolicy: req.PINComplexityPolicy,
	}

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := appconfig.BuildMinPINLengthPreview(status, minReq, mode)
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
		fallbackMessage: "Set minimum PIN length on authenticator " + r.env.Selected.Fingerprint + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	err = r.runWithOptionalToken(ctx, protocol.PermissionAuthenticatorConfiguration, "", func(token []byte) error {
		return r.env.Authenticator.SetMinPINLength(ctx, token, protocol.SetMinPINLengthConfigSubCommandParams{
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

	output.Result = new(appconfig.MinPINLengthResult(r.env.Selected.Fingerprint, minReq))
	return output, nil
}
