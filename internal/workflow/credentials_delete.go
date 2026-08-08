package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) DeleteCredential(
	ctx context.Context,
	device authenticator.CredentialManager,
	req appcredentials.DeleteOperation,
) (appcredentials.DeleteOutput, error) {
	inventoryPermission, mutationPermission, command, err := r.inventoryMutationPermissions(
		ctx,
		device,
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}

	report, err := r.credentialInventory(
		ctx,
		device,
		inventoryPermission,
		nil,
	)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}
	preview, err := rtcredentials.BuildDeletePreview(report, req.CredentialIDHex)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}

	if req.DryRun {
		return appcredentials.DeleteOutput{Preview: preview}, nil
	}

	publicTarget, err := rtcredentials.FindByHexID(report, req.CredentialIDHex)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}

	descriptor, err := credentialDescriptor(publicTarget.Record)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		r.recordStateEffect(rtruntime.StateEffectCredentialInventoryChanged)

		return device.DeleteCredential(ctx, token, descriptor)
	})
	if err != nil {
		return appcredentials.DeleteOutput{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			command,
			protocol.CredentialManagementSubCommandDeleteCredential,
		))
	}
	result := appcredentials.DeleteResult{
		AttachmentID:    r.env.Selected.Attachment.ID,
		CredentialIDHex: publicTarget.Record.CredentialIDHex,
		RPID:            publicTarget.RP.ID,
		RPName:          publicTarget.RP.Name,
		UserIDHex:       publicTarget.User.UserIDHex,
		UserName:        publicTarget.User.Name,
		DisplayName:     publicTarget.User.DisplayName,
	}

	return appcredentials.DeleteOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}
