package runtime

import (
	"context"
	"errors"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

type TokenKey struct {
	Permission protocol.Permission
	RPID       string
}

// Covers reports whether a cached grant can satisfy the requested token key.
func (granted TokenKey) Covers(requested TokenKey) bool {
	if requested.Permission == protocol.PermissionNone || granted.RPID != requested.RPID {
		return false
	}

	if requested.Permission == protocol.PermissionPersistentCredentialManagementReadOnly &&
		granted.Permission&protocol.PermissionCredentialManagement != 0 {
		return true
	}

	return granted.Permission&requested.Permission == requested.Permission
}

type TokenCache interface {
	GetToken(TokenKey) ([]byte, bool, error)
	SetToken(TokenKey, *secret.Handle)
	InvalidateToken()
	InvalidateTokenUnlessPermission(protocol.Permission)
}

func (s *TokenService) Invalidate() {
	s.cache.InvalidateToken()
}

func (s *TokenService) InvalidateUnlessPermission(permission protocol.Permission) {
	s.cache.InvalidateTokenUnlessPermission(permission)
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
			Permission: permissionLabel(permission),
		})
		if err != nil {
			return nil, err
		}

		token, err = authenticator.GetPinUvAuthTokenUsingUV(ctx, permission, key.RPID)
		if err == nil {
			return s.storeToken(key, token), nil
		}

		if !fallbackToPIN(err) {
			return nil, errornorm.Annotate(err, errornorm.WithCommand(
				failure.PhaseTokenAcquisition,
				protocol.AuthenticatorClientPIN,
			))
		}
	}

	var previousFailure *failure.Failure
	for {
		pinInteraction, err := readPINInteractionState(ctx, authenticator)
		if err != nil {
			return nil, err
		}
		pinInteraction.Failure = previousFailure

		token, err = s.acquireUsingPIN(ctx, authenticator, permission, key.RPID, pinInteraction)
		if err == nil {
			return s.storeToken(key, token), nil
		}

		normalized := errornorm.Normalize(err, "")
		if !failure.IsCode(normalized, failure.CodePINInvalid) {
			return nil, normalized
		}

		previousFailure = failure.Snapshot(normalized)
	}
}

// Use runs a replay-safe token consumer and retries it once when the
// authenticator rejects a token that can be safely reacquired. Callers must
// ensure that replaying the entire consumer cannot repeat a mutation.
func (s *TokenService) Use(
	ctx context.Context,
	authenticator authenticator.TokenProvider,
	permission protocol.Permission,
	rpID string,
	use func([]byte) error,
) error {
	retriedRejectedToken := false
	for {
		token, err := s.Acquire(ctx, authenticator, permission, rpID)
		if err != nil {
			return err
		}

		err = func() error {
			defer secret.Zero(token)

			return use(token)
		}()
		if err == nil {
			return nil
		}

		normalized := errornorm.Normalize(err, "")
		if normalized.Code != failure.CodePINUVAuthInvalid {
			return err
		}

		s.cache.InvalidateToken()

		if retriedRejectedToken {
			return err
		}

		retriedRejectedToken = true
	}
}

func readPINInteractionState(
	ctx context.Context,
	authenticator authenticator.TokenProvider,
) (*model.PINInteractionState, error) {
	retries, powerCycleState, err := authenticator.GetPINRetries(ctx)
	if err != nil {
		return nil, errornorm.Normalize(errornorm.Annotate(
			err,
			errornorm.WithClientPINSubCommand(
				failure.PhaseTokenAcquisition,
				protocol.ClientPINSubCommandGetPINRetries,
			)), "")
	}

	return &model.PINInteractionState{
		RetriesRemaining: new(retries),
		PowerCycleState:  powerCycleState,
	}, nil
}

func (s *TokenService) acquireUsingPIN(
	ctx context.Context,
	authenticator authenticator.TokenProvider,
	permission protocol.Permission,
	rpID string,
	pinInteraction *model.PINInteractionState,
) ([]byte, error) {
	response, err := s.interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Permission: permissionLabel(permission),
		PINState:   pinInteraction,
	})
	if err != nil {
		return nil, err
	}
	defer secret.Zero(response.PIN)

	token, err := authenticator.GetPinUvAuthTokenUsingPIN(ctx, string(response.PIN), permission, rpID)
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseTokenAcquisition,
			protocol.AuthenticatorClientPIN,
		))
	}

	return token, nil
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
