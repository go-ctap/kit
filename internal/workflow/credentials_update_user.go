package workflow

import (
	"context"
	"encoding/hex"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	rtcredentials "github.com/go-ctap/kit/internal/credentials"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) UpdateCredentialUser(
	ctx context.Context,
	device authenticator.CredentialManager,
	req appcredentials.UpdateUserOperation,
) (appcredentials.UpdateUserOutput, error) {
	preview, err := rtcredentials.BuildUpdateUserPreview(req)
	if err != nil {
		return appcredentials.UpdateUserOutput{}, err
	}

	if req.DryRun {
		return appcredentials.UpdateUserOutput{Preview: preview}, nil
	}

	_, mutationPermission, command, err := r.inventoryMutationPermissions(
		ctx,
		device,
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return appcredentials.UpdateUserOutput{}, err
	}

	userID, err := decodeCredentialHex(preview.Proposed.UserIDHex)
	if err != nil {
		return appcredentials.UpdateUserOutput{}, err
	}

	descriptor, err := credentialDescriptor(req.Target.Record)
	if err != nil {
		return appcredentials.UpdateUserOutput{}, err
	}

	updatedUser := credential.PublicKeyCredentialUserEntity{
		ID:          userID,
		Name:        preview.Proposed.Name,
		DisplayName: preview.Proposed.DisplayName,
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: mutationPermission,
	}, func(token []byte) error {
		r.recordStateEffect(rtruntime.StateEffectCredentialInventoryChanged)

		return device.UpdateUserInformation(ctx, token, descriptor, updatedUser)
	})
	if err != nil {
		return appcredentials.UpdateUserOutput{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			command,
			protocol.CredentialManagementSubCommandUpdateUserInformation,
		))
	}
	result := appcredentials.UpdateUserResult{
		AttachmentID:    r.env.Selected.Attachment.ID,
		CredentialIDHex: req.Target.Record.CredentialIDHex,
		RPID:            req.Target.RP.ID,
		RPName:          req.Target.RP.Name,
		Previous:        req.Target.User,
		Current:         preview.Proposed,
	}

	return appcredentials.UpdateUserOutput{
		Preview: preview,
		Result:  &result,
	}, nil
}

func decodeCredentialHex(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, failure.Wrap(
			failure.CodeUserIDHexInvalid,
			err,
			failure.WithPhase(failure.PhaseDecode),
		)
	}

	return decoded, nil
}
