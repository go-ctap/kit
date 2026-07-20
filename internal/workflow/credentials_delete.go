package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	rtcredentials "github.com/go-ctap/kit/internal/credentials"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) DeleteCredential(
	ctx context.Context,
	device authenticator.CredentialManager,
	req appcredentials.DeleteOperation,
) (appcredentials.DeleteOutput, error) {
	var output appcredentials.DeleteOutput

	inventoryPermission, mutationPermission, err := r.inventoryMutationPermissions(
		ctx,
		device,
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return output, err
	}

	report, err := r.credentialInventory(
		ctx,
		device,
		inventoryPermission,
		nil,
	)
	if err != nil {
		return output, err
	}
	preview, err := rtcredentials.BuildDeletePreview(report, req.CredentialIDHex)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	publicTarget, err := rtcredentials.FindByHexID(report, req.CredentialIDHex)
	if err != nil {
		return output, err
	}

	descriptor, err := credentialDescriptor(publicTarget.Record)
	if err != nil {
		return output, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		return device.DeleteCredential(ctx, token, descriptor)
	})
	if err != nil {
		info, infoErr := r.getAuthenticatorInfo(ctx, device)
		if infoErr != nil {
			return output, infoErr
		}
		return output, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			credentialManagementCommand(info),
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
