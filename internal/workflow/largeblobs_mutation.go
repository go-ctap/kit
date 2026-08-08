package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func (r Runner) WriteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.WriteOperation,
) (applargeblobs.MutationOutput, error) {
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

	preview, err := buildWritePreviewFromState(state, req.Payload)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	if req.DryRun {
		return applargeblobs.MutationOutput{Preview: preview}, nil
	}

	plan, err := buildWriteMutationPlan(state, req.Payload)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		r.recordStateEffect(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, plan.replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(plan.replacement)
	r.recordStateEffect(rtruntime.StateEffectLargeBlobSnapshotSynchronized)
	result := plan.result(state)

	return applargeblobs.MutationOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func (r Runner) DeleteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.DeleteOperation,
) (applargeblobs.MutationOutput, error) {
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

	preview, err := buildDeletePreviewFromState(state)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	if req.DryRun {
		return applargeblobs.MutationOutput{Preview: preview}, nil
	}

	plan, err := buildDeleteMutationPlan(state)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	if plan.noop {
		result := plan.result(state)

		return applargeblobs.MutationOutput{
			Preview: preview,
			Result:  &result,
		}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		r.recordStateEffect(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, plan.replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(plan.replacement)
	r.recordStateEffect(rtruntime.StateEffectLargeBlobSnapshotSynchronized)
	result := plan.result(state)

	return applargeblobs.MutationOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
