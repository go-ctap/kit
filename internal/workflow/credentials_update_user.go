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
	var output appcredentials.UpdateUserOutput

	preview, err := rtcredentials.BuildUpdateUserPreview(req)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	_, mutationPermission, err := r.inventoryMutationPermissions(
		ctx,
		device,
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return output, err
	}

	userID, err := decodeCredentialHex(preview.Proposed.UserIDHex)
	if err != nil {
		return output, err
	}

	descriptor, err := credentialDescriptor(req.Target.Record)
	if err != nil {
		return output, err
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
		info, infoErr := r.getAuthenticatorInfo(ctx, device)
		if infoErr != nil {
			return output, infoErr
		}
		return output, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			credentialManagementCommand(info),
			protocol.CredentialManagementSubCommandUpdateUserInformation,
		))
	}
	result := appcredentials.UpdateUserResult{
		DeviceFingerprint: r.env.Selected.Fingerprint,
		CredentialIDHex:   req.Target.Record.CredentialIDHex,
		RPID:              req.Target.RP.ID,
		RPName:            req.Target.RP.Name,
		Previous:          req.Target.User,
		Current:           preview.Proposed,
	}

	output.Result = &result

	return output, nil
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
