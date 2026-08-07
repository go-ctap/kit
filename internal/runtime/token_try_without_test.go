package runtime

import (
	"context"
	"errors"
	"slices"
	"testing"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
)

func TestTokenServiceUseTryWithoutTokenAcquiresOnlyWhenRequired(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		VerificationFlowDefault,
	)

	var usedTokens [][]byte
	err := tokens.Use(
		context.Background(),
		TokenUse{
			Permission:      protocol.PermissionMakeCredential,
			RPID:            "example.com",
			TryWithoutToken: true,
		},
		func(token []byte) error {
			usedTokens = append(usedTokens, token)
			if token == nil {
				return ctapdevice.ErrPinUvAuthTokenRequired
			}

			return nil
		},
	)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}

	if got := len(usedTokens); got != 2 {
		t.Fatalf("token uses = %d, want 2", got)
	}

	if usedTokens[0] != nil {
		t.Fatalf("initial token = %q, want nil", usedTokens[0])
	}

	if !slices.Equal(usedTokens[1], make([]byte, len(usedTokens[1]))) {
		t.Fatalf("acquired token was not zeroed: %#v", usedTokens[1])
	}

	if want := []string{"example.com"}; !slices.Equal(authenticator.uvRPIDs, want) {
		t.Fatalf("UV token rpIds = %v, want %v", authenticator.uvRPIDs, want)
	}

	if got := len(requests); got != 1 {
		t.Fatalf("interactions = %d, want 1", got)
	}
}

func TestTokenServiceUseTryWithoutTokenBeforeCachedToken(t *testing.T) {
	cache := &testTokenCache{}
	key := TokenKey{Permission: protocol.PermissionMakeCredential, RPID: "example.com"}
	cache.SetToken(key, secret.New([]byte("cached-token")))
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(cache, authenticator, nil, VerificationFlowDefault)

	uses := 0
	err := tokens.Use(
		context.Background(),
		TokenUse{
			Permission:      protocol.PermissionMakeCredential,
			RPID:            "example.com",
			TryWithoutToken: true,
		},
		func(token []byte) error {
			uses++
			if token != nil {
				t.Fatalf("token = %q, want nil", token)
			}

			return nil
		},
	)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}

	if uses != 1 {
		t.Fatalf("token uses = %d, want 1", uses)
	}

	if _, present := cache.GetToken(key); !present {
		t.Fatal("unused cached token was invalidated")
	}

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}
}

func TestTokenServiceUseTryWithoutTokenDoesNotReplayRejectedToken(t *testing.T) {
	cache := &testTokenCache{}
	key := TokenKey{Permission: protocol.PermissionMakeCredential, RPID: "example.com"}
	cache.SetToken(key, secret.New([]byte("cached-token")))
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(cache, authenticator, nil, VerificationFlowDefault)
	consumerErr := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorMakeCredential,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
	}

	uses := 0
	err := tokens.Use(
		context.Background(),
		TokenUse{
			Permission:      protocol.PermissionMakeCredential,
			RPID:            "example.com",
			TryWithoutToken: true,
		},
		func(token []byte) error {
			uses++
			if token == nil {
				return ctapdevice.ErrPinUvAuthTokenRequired
			}

			return consumerErr
		},
	)
	if !errors.Is(err, consumerErr) {
		t.Fatalf("Use error = %v, want consumer error", err)
	}

	if uses != 2 {
		t.Fatalf("token uses = %d, want 2", uses)
	}

	if _, present := cache.GetToken(key); present {
		t.Fatal("rejected token remained cached")
	}

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}
}
