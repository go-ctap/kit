package workflow

import (
	"context"
	"errors"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func (r Runner) writeLargeBlob(ctx context.Context, req model.WriteLargeBlobOperation) (model.OperationResult, error) {
	var output model.LargeBlobMutationOutput

	inventory, err := r.readCredentialInventoryReport(ctx)
	if err != nil {
		return output, err
	}

	state, err := r.loadTargetBlobState(inventory, req.CredentialIDHex)
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
		declinedErr:     applargeblobs.ErrConfirmationRequired,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	replacement, result, err := buildWriteMutation(state, req.Payload)
	if err != nil && errors.Is(err, applargeblobs.ErrLargeBlobArrayTooBig) && result.CredentialIDHex != "" {
		output.Result = &result
	}
	if err != nil {
		return output, err
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionLargeBlobWrite, "")
	if err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithLargeBlobsSubCommand(
			model.OperationWriteLargeBlob,
			ctaperrors.LargeBlobsSubCommandSet,
		))
	}
	defer secret.Zero(token)

	if err := r.largeBlobManager().SetLargeBlobs(token, replacement); err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithLargeBlobsSubCommand(
			model.OperationWriteLargeBlob,
			ctaperrors.LargeBlobsSubCommandSet,
		))
	}

	output.Result = &result

	return output, nil
}

func (r Runner) deleteLargeBlob(ctx context.Context, req model.DeleteLargeBlobOperation) (model.OperationResult, error) {
	var output model.LargeBlobMutationOutput

	inventory, err := r.readCredentialInventoryReport(ctx)
	if err != nil {
		return output, err
	}

	state, err := r.loadTargetBlobState(inventory, req.CredentialIDHex)
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
		declinedErr:     applargeblobs.ErrConfirmationRequired,
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

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionLargeBlobWrite, "")
	if err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithLargeBlobsSubCommand(
			model.OperationDeleteLargeBlob,
			ctaperrors.LargeBlobsSubCommandSet,
		))
	}
	defer secret.Zero(token)

	if err := r.largeBlobManager().SetLargeBlobs(token, replacement); err != nil {
		return output, ctaperrors.Annotate(err, ctaperrors.WithLargeBlobsSubCommand(
			model.OperationDeleteLargeBlob,
			ctaperrors.LargeBlobsSubCommandSet,
		))
	}

	output.Result = &result

	return output, nil
}
