package workflow

import (
	"context"
	"encoding/hex"

	ctapauthenticator "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) credentialStoreState(ctx context.Context) (appcredentials.StoreStateResult, error) {
	if r.env.Cache != nil {
		r.env.Cache.InvalidateTokenUnlessPermission(protocol.PermissionPersistentCredentialManagementReadOnly)
	}

	var state ctapauthenticator.PersistentCredentialStoreState
	err := r.env.Tokens.Use(
		ctx,
		r.tokenProvider(),
		protocol.PermissionPersistentCredentialManagementReadOnly,
		"",
		func(token []byte) error {
			var err error
			state, err = r.credentialManager().GetPersistentCredentialStoreState(ctx, token)

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
