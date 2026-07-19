package workflow

import (
	"context"
	"encoding/hex"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) updateCredentialUser(ctx context.Context, req model.UpdateCredentialUserOperation) (model.CredentialUpdateOutput, error) {
	var output model.CredentialUpdateOutput

	updateReq := appcredentials.UpdateUserRequest{
		UserIDHex:       req.UserIDHex,
		Name:            req.Name,
		DisplayName:     req.DisplayName,
		UserIDProvided:  req.UserIDProvided,
		NameProvided:    req.NameProvided,
		DisplayProvided: req.DisplayProvided,
	}

	preview, err := appcredentials.BuildUpdateUserPreview(req.Target, updateReq)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	_, mutationPermission, err := r.inventoryMutationPermissions(
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
		return r.env.Authenticator.UpdateUserInformation(ctx, token, descriptor, updatedUser)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			credentialManagementCommand(r.env.Authenticator.GetInfo()),
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
