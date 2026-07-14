package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) deleteCredential(ctx context.Context, req model.DeleteCredentialOperation) (model.OperationResult, error) {
	var output model.CredentialDeleteOutput

	report, err := r.readCredentialInventoryReport(ctx)
	if err != nil {
		return output, err
	}
	defer zeroCredentialInventoryReport(&report)

	preview, err := appcredentials.BuildDeletePreview(report, req.CredentialIDHex)
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
		fallbackMessage: "Delete resident credential " + req.CredentialIDHex + "?",
		destructive:     true,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	publicTarget, err := appcredentials.FindCredentialByHexID(report, req.CredentialIDHex)
	if err != nil {
		return output, err
	}

	descriptor, err := credentialDescriptor(publicTarget.Record)
	if err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(
		ctx,
		r.tokenProvider(),
		protocol.PermissionCredentialManagement,
		r.credentialMutationRPID(publicTarget),
	)
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	if err := r.credentialManager().DeleteCredential(ctx, token, descriptor); err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			credentialManagementCommand(r.infoProvider().GetInfo()),
			protocol.CredentialManagementSubCommandDeleteCredential,
		))
	}

	result := appcredentials.DeleteResult{
		DeviceFingerprint: r.env.Selected.Fingerprint,
		CredentialIDHex:   publicTarget.Record.CredentialIDHex,
		RPID:              publicTarget.RP.ID,
		RPName:            publicTarget.RP.Name,
		UserIDHex:         publicTarget.User.UserIDHex,
		UserName:          publicTarget.User.Name,
		DisplayName:       publicTarget.User.DisplayName,
	}

	output.Result = &result

	return output, nil
}
