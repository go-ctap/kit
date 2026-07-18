package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) writeLargeBlob(ctx context.Context, req model.WriteLargeBlobOperation) (model.OperationResult, error) {
	var output model.LargeBlobMutationOutput

	inventoryPermission, mutationPermission, err := r.inventoryMutationPermissions(
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return output, err
	}

	inventory, err := r.credentialInventoryReport(
		ctx,
		inventoryPermission,
	)
	if err != nil {
		return output, err
	}

	state, err := r.loadTargetBlobState(ctx, inventory, req.CredentialIDHex)
	zeroCredentialInventoryReport(&inventory)

	if err != nil {
		return output, err
	}

	defer state.zero()

	preview, err := buildWritePreviewFromState(state, req.Payload)
	output.Preview = preview
	if err != nil {
		return output, err
	}

	if req.DryRun {
		return output, nil
	}

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Write large blob for credential " + req.CredentialIDHex + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	replacement, result, err := buildWriteMutation(state, req.Payload)
	if err != nil && failure.IsCode(err, failure.CodeLargeBlobArrayTooLarge) && result.CredentialIDHex != "" {
		output.Result = &result
	}
	if err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.env.Authenticator, mutationPermission, "")
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	err = r.env.Authenticator.SetLargeBlobs(ctx, token, replacement)
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	output.Result = &result

	return output, nil
}

func (r Runner) deleteLargeBlob(ctx context.Context, req model.DeleteLargeBlobOperation) (model.OperationResult, error) {
	var output model.LargeBlobMutationOutput

	inventoryPermission, mutationPermission, err := r.inventoryMutationPermissions(
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return output, err
	}

	inventory, err := r.credentialInventoryReport(
		ctx,
		inventoryPermission,
	)
	if err != nil {
		return output, err
	}

	state, err := r.loadTargetBlobState(ctx, inventory, req.CredentialIDHex)
	zeroCredentialInventoryReport(&inventory)

	if err != nil {
		return output, err
	}

	defer state.zero()

	preview, err := buildDeletePreviewFromState(state)
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
		fallbackMessage: "Delete large blob for credential " + req.CredentialIDHex + "?",
		destructive:     true,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	replacement, result, noBlob, err := buildDeleteMutation(state)
	if err != nil {
		return output, err
	}

	if noBlob {
		output.Result = &result

		return output, nil
	}

	token, err := r.env.Tokens.Acquire(ctx, r.env.Authenticator, mutationPermission, "")
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	err = r.env.Authenticator.SetLargeBlobs(ctx, token, replacement)
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	output.Result = &result

	return output, nil
}
