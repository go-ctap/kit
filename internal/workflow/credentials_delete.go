package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) deleteCredential(ctx context.Context, req model.DeleteCredentialOperation) (model.CredentialDeleteOutput, error) {
	var output model.CredentialDeleteOutput

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

	preview, err := appcredentials.BuildDeletePreview(report, req.CredentialIDHex)
	if err != nil {
		return output, err
	}

	output.Preview = preview

	if req.DryRun {
		return output, nil
	}

	publicTarget, err := appcredentials.FindCredentialByHexID(report, req.CredentialIDHex)
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
		return r.env.Authenticator.DeleteCredential(ctx, token, descriptor)
	})
	if err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			credentialManagementCommand(r.env.Authenticator.GetInfo()),
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
