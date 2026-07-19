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
	req applargeblobs.WriteOperation,
) (applargeblobs.MutationOutput, error) {
	var output applargeblobs.MutationOutput

	inventoryPermission, mutationPermission, err := r.inventoryMutationPermissions(
		device,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return output, err
	}

	inventory, err := r.credentialInventoryReport(
		ctx,
		device,
		inventoryPermission,
	)
	if err != nil {
		return output, err
	}
	defer zeroCredentialInventoryReport(&inventory)

	state, err := r.loadTargetBlobState(ctx, device, inventory, req.CredentialIDHex)
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

	replacement, result, err := buildWriteMutation(state, req.Payload)
	if err != nil && failure.IsCode(err, failure.CodeLargeBlobArrayTooLarge) && result.CredentialIDHex != "" {
		output.Result = &result
	}

	if err != nil {
		return output, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		return device.SetLargeBlobs(ctx, token, replacement)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	output.Result = &result

	return output, nil
}

func (r Runner) DeleteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	req applargeblobs.DeleteOperation,
) (applargeblobs.MutationOutput, error) {
	var output applargeblobs.MutationOutput

	inventoryPermission, mutationPermission, err := r.inventoryMutationPermissions(
		device,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return output, err
	}

	inventory, err := r.credentialInventoryReport(
		ctx,
		device,
		inventoryPermission,
	)
	if err != nil {
		return output, err
	}
	defer zeroCredentialInventoryReport(&inventory)

	state, err := r.loadTargetBlobState(ctx, device, inventory, req.CredentialIDHex)
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

	replacement, result, noBlob, err := buildDeleteMutation(state)
	if err != nil {
		return output, err
	}

	if noBlob {
		output.Result = &result

		return output, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		return device.SetLargeBlobs(ctx, token, replacement)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	output.Result = &result

	return output, nil
}
