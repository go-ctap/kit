package runtime

import (
	"context"
	"errors"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
)

type TokenKey struct {
	Permission protocol.Permission
	RPID       string
}

type TokenCache interface {
	GetToken(TokenKey) ([]byte, bool, error)
	SetToken(TokenKey, *secret.Handle)
	InvalidateToken()
}

type TokenService struct {
	cache            TokenCache
	verificationFlow model.VerificationFlow
	interactions     interface {
		RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
	}
}

func NewTokenService(
	cache TokenCache,
	interactions interface {
		RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
	},
	verificationFlow model.VerificationFlow,
) *TokenService {
	return &TokenService{
		cache:            cache,
		verificationFlow: verificationFlow,
		interactions:     interactions,
	}
}

func (s *TokenService) Acquire(
	ctx context.Context,
	authenticator authenticator.TokenProvider,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	key := TokenKey{
		Permission: permission,
		RPID:       rpID,
	}

	if token, ok, _ := s.cache.GetToken(key); ok {
		return token, nil
	}

	var (
		token []byte
		err   error
	)

	if s.verificationFlow != model.VerificationFlowPIN &&
		supportsUserVerificationForPermission(authenticator.GetInfo(), permission) {
		_, err = s.interactions.RequestInteraction(ctx, model.InteractionRequest{
			Kind:       model.InteractionKindUserVerification,
			Permission: permission.String(),
		})
		if err != nil {
			return nil, err
		}

		token, err = authenticator.GetPinUvAuthTokenUsingUV(ctx, permission, key.RPID)
		if err == nil {
			return s.storeToken(key, token), nil
		}

		if !fallbackToPIN(err) {
			return nil, ctaperrors.Annotate(err, ctaperrors.WithClientPINSubCommand(
				"",
				protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
			))
		}
	}

	response, err := s.interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Permission: permission.String(),
	})
	if err != nil {
		return nil, err
	}
	defer secret.Zero(response.PIN)

	token, err = authenticator.GetPinUvAuthTokenUsingPIN(ctx, string(response.PIN), permission, key.RPID)
	if err != nil {
		return nil, ctaperrors.Annotate(err, ctaperrors.WithClientPINSubCommand(
			"",
			protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		))
	}

	return s.storeToken(key, token), nil
}

func (s *TokenService) storeToken(key TokenKey, token []byte) []byte {
	handle := secret.New(token)

	s.cache.SetToken(key, handle)

	out, _ := handle.Bytes()
	return out
}

func supportsUserVerificationForPermission(
	info protocol.AuthenticatorGetInfoResponse,
	permission protocol.Permission,
) bool {
	if !info.Options[protocol.OptionPinUvAuthToken] || !info.Options[protocol.OptionUserVerification] {
		return false
	}

	if permission&protocol.PermissionBioEnrollment != 0 && !info.Options[protocol.OptionUvBioEnroll] {
		return false
	}

	if permission&protocol.PermissionAuthenticatorConfiguration != 0 && !info.Options[protocol.OptionUvAcfg] {
		return false
	}

	return true
}

func fallbackToPIN(err error) bool {
	if errors.Is(err, ctapdevice.ErrNotSupported) || errors.Is(err, ctapdevice.ErrUvNotConfigured) {
		return true
	}

	ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err)
	return ok && ctapErr.StatusCode == ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION
}
