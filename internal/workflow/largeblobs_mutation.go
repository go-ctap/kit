package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func (r Runner) WriteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.WriteOperation,
) (applargeblobs.MutationOutput, error) {
	var output applargeblobs.MutationOutput

	inventoryPermission, mutationPermission, _, err := r.inventoryMutationPermissions(
		ctx,
		device,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	inventory, err := r.loadLargeBlobInventory(
		ctx,
		device,
		largeBlobState,
		inventoryPermission,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	state, err := r.loadTargetBlobState(ctx, device, inventory, req.CredentialIDHex)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	defer state.zero()

	preview, err := buildWritePreviewFromState(state, req.Payload)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}
	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	replacement, result, err := buildWriteMutation(state, req.Payload)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		r.recordStateEffect(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(replacement)
	r.recordStateEffect(rtruntime.StateEffectLargeBlobSnapshotSynchronized)
	output.Result = &result

	return output, nil
}

func (r Runner) DeleteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.DeleteOperation,
) (applargeblobs.MutationOutput, error) {
	var output applargeblobs.MutationOutput

	inventoryPermission, mutationPermission, _, err := r.inventoryMutationPermissions(
		ctx,
		device,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	inventory, err := r.loadLargeBlobInventory(
		ctx,
		device,
		largeBlobState,
		inventoryPermission,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	state, err := r.loadTargetBlobState(ctx, device, inventory, req.CredentialIDHex)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	defer state.zero()

	preview, err := buildDeletePreviewFromState(state)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	replacement, result, noBlob, err := buildDeleteMutation(state)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	if noBlob {
		output.Result = &result

		return output, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		r.recordStateEffect(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(replacement)
	r.recordStateEffect(rtruntime.StateEffectLargeBlobSnapshotSynchronized)
	output.Result = &result

	return output, nil
}
