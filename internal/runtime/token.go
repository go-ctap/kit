package runtime

import (
	"context"
	"errors"

	"github.com/go-ctap/ctaphid/pkg/ctaphid"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	ctapdevice "github.com/go-ctap/ctaphid/pkg/device"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
)

type TokenKey struct {
	Permission ctaptypes.Permission
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
	permission ctaptypes.Permission,
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

		token, err = authenticator.GetPinUvAuthTokenUsingUV(permission, key.RPID)
		if err == nil {
			return s.storeToken(key, token), nil
		}

		if !fallbackToPIN(err) {
			return nil, ctaperrors.Annotate(err, ctaperrors.WithClientPINSubCommand(
				"",
				ctaptypes.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
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

	token, err = authenticator.GetPinUvAuthTokenUsingPIN(string(response.PIN), permission, key.RPID)
	if err != nil {
		return nil, ctaperrors.Annotate(err, ctaperrors.WithClientPINSubCommand(
			"",
			ctaptypes.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
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
	info ctaptypes.AuthenticatorGetInfoResponse,
	permission ctaptypes.Permission,
) bool {
	if !info.Options[ctaptypes.OptionPinUvAuthToken] || !info.Options[ctaptypes.OptionUserVerification] {
		return false
	}

	if permission&ctaptypes.PermissionBioEnrollment != 0 && !info.Options[ctaptypes.OptionUvBioEnroll] {
		return false
	}

	if permission&ctaptypes.PermissionAuthenticatorConfiguration != 0 && !info.Options[ctaptypes.OptionUvAcfg] {
		return false
	}

	return true
}

func fallbackToPIN(err error) bool {
	if errors.Is(err, ctapdevice.ErrNotSupported) || errors.Is(err, ctapdevice.ErrUvNotConfigured) {
		return true
	}

	ctapErr, ok := errors.AsType[*ctaphid.CTAPError](err)
	return ok && ctapErr.StatusCode == ctaphid.CTAP2_ERR_UNAUTHORIZED_PERMISSION
}
