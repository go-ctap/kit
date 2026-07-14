package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func (r Runner) setAlwaysUV(ctx context.Context, req model.SetAlwaysUVOperation) (model.OperationResult, error) {
	var output model.AuthenticatorConfigOutput

	status := r.statusReport()

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
		fallbackMessage: "Set alwaysUv " + string(req.Target) + " on authenticator " + r.env.Selected.DeviceID + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionAuthenticatorConfiguration, "")
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	if err := r.configManager().ToggleAlwaysUV(ctx, token); err != nil {
		return output, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandToggleAlwaysUv,
		))
	}

	output.Result = new(appconfig.AlwaysUVResult(
		r.env.Selected.DeviceID,
		req.Target,
		preview.RequestedAlwaysUV,
	))
	return output, nil
}

func (r Runner) setMinPINLength(ctx context.Context, req model.SetMinPINLengthOperation) (model.OperationResult, error) {
	var output model.AuthenticatorConfigOutput

	status := r.statusReport()
	minReq := appconfig.MinPINLengthRequest{
		Length:              req.Length,
		RPIDs:               req.RPIDs,
		ForceChangePin:      req.ForceChangePin,
		PinComplexityPolicy: req.PinComplexityPolicy,
		Confirmed:           req.Confirmed,
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
		fallbackMessage: "Set minimum PIN length on authenticator " + r.env.Selected.DeviceID + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionAuthenticatorConfiguration, "")
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	if err := r.configManager().SetMinPINLength(
		ctx,
		token,
		req.Length,
		req.RPIDs,
		req.ForceChangePin,
		req.PinComplexityPolicy,
	); err != nil {
		return output, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandSetMinPINLength,
		))
	}

	output.Result = new(appconfig.MinPINLengthResult(r.env.Selected.DeviceID, req.Length))
	return output, nil
}
