package workflow

import (
	"context"
	"encoding/hex"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) updateCredentialUser(ctx context.Context, req model.UpdateCredentialUserOperation) (model.OperationResult, error) {
	var output model.CredentialUpdateOutput

	inventoryPermission, mutationPermission, err := r.inventoryMutationPermissions(
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return output, err
	}

	report, err := r.credentialInventoryReport(
		ctx,
		inventoryPermission,
	)
	if err != nil {
		return output, err
	}
	defer zeroCredentialInventoryReport(&report)

	updateReq := appcredentials.UpdateUserRequest{
		CredentialIDHex: req.CredentialIDHex,
		UserIDHex:       req.UserIDHex,
		Name:            req.Name,
		DisplayName:     req.DisplayName,
		UserIDProvided:  req.UserIDProvided,
		NameProvided:    req.NameProvided,
		DisplayProvided: req.DisplayProvided,
		Confirmed:       req.Confirmed,
	}

	preview, err := appcredentials.BuildUpdateUserPreview(report, updateReq)
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
		fallbackMessage: "Update resident credential " + req.CredentialIDHex + "?",
		destructive:     false,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	updateReq.Confirmed = true

	publicTarget, err := appcredentials.FindCredentialByHexID(report, req.CredentialIDHex)
	if err != nil {
		return output, err
	}

	proposed, err := appcredentials.ResolveUpdatedUser(publicTarget, updateReq)
	if err != nil {
		return output, err
	}

	userID, err := decodeCredentialHex(proposed.UserIDHex)
	if err != nil {
		return output, err
	}

	descriptor, err := credentialDescriptor(publicTarget.Record)
	if err != nil {
		return output, err
	}

	updatedUser := credential.PublicKeyCredentialUserEntity{
		ID:          userID,
		Name:        proposed.Name,
		DisplayName: proposed.DisplayName,
	}

	token, err := r.env.Tokens.Acquire(
		ctx,
		r.env.Authenticator,
		mutationPermission,
		r.credentialMutationRPID(publicTarget),
	)
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	err = r.env.Authenticator.UpdateUserInformation(ctx, token, descriptor, updatedUser)
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			credentialManagementCommand(r.env.Authenticator.GetInfo()),
			protocol.CredentialManagementSubCommandUpdateUserInformation,
		))
	}

	result := appcredentials.UpdateUserResult{
		DeviceFingerprint: r.env.Selected.Fingerprint,
		CredentialIDHex:   publicTarget.Record.CredentialIDHex,
		RPID:              publicTarget.RP.ID,
		RPName:            publicTarget.RP.Name,
		Previous:          publicTarget.User,
		Current:           proposed,
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
