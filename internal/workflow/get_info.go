package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) getAuthenticatorInfo(
	ctx context.Context,
	device authenticator.InfoProvider,
) (protocol.AuthenticatorGetInfoResponse, error) {
	info, err := authenticator.ResolveInfo(ctx, device)
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, errornorm.Annotate(
			err,
			errornorm.WithCommand(failure.PhaseAuthenticatorCommand, protocol.AuthenticatorGetInfo),
		)
	}
	return info, nil
}
