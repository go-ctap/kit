package workflow

import (
	"context"
	"encoding/hex"

	ctapauthenticator "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) credentialStoreState(ctx context.Context) (appcredentials.StoreStateResult, error) {
	r.env.Tokens.InvalidateUnlessPermission(protocol.PermissionPersistentCredentialManagementReadOnly)

	var state ctapauthenticator.PersistentCredentialStoreState
	err := r.env.Tokens.Use(
		ctx,
		rtruntime.TokenUse{
			Permission: protocol.PermissionPersistentCredentialManagementReadOnly,
			ReplaySafe: true,
		},
		func(token []byte) error {
			var err error
			state, err = r.env.Authenticator.GetPersistentCredentialStoreState(ctx, token)

			return err
		},
	)
	if err != nil {
		return appcredentials.StoreStateResult{}, errornorm.Annotate(
			err,
			errornorm.WithCommand(failure.PhaseAuthenticatorCommand, protocol.AuthenticatorGetInfo),
		)
	}

	return appcredentials.StoreStateResult{
		AuthenticatorIdentifierHex: hex.EncodeToString(state.AuthenticatorIdentifier[:]),
		CredentialStoreStateHex:    hex.EncodeToString(state.CredentialStoreState[:]),
	}, nil
}
