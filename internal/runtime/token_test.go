package runtime

import (
	"context"
	"slices"
	"testing"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	"github.com/samber/lo"
)

func TestTokenServiceCachesByPermissionAndRPID(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		model.VerificationFlowDefault,
	)

	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")
	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")
	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "example.com")
	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")

	wantRPIDs := []string{"", "example.com", ""}
	if !slices.Equal(authenticator.uvRPIDs, wantRPIDs) {
		t.Fatalf("UV token rpIds = %v, want %v", authenticator.uvRPIDs, wantRPIDs)
	}

	if len(requests) != len(wantRPIDs) {
		t.Fatalf("interactions = %d, want %d", len(requests), len(wantRPIDs))
	}
}

func TestTokenServiceDefaultFlowRequestsUVInteractionBeforeUVCommand(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info:     uvTokenInfo(),
		requests: &requests,
	}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		model.VerificationFlowDefault,
	)

	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")

	if len(requests) != 1 {
		t.Fatalf("interactions = %d, want 1", len(requests))
	}

	if requests[0].Kind != model.InteractionKindUserVerification {
		t.Fatalf("interaction kind = %s, want user-verification", requests[0].Kind)
	}

	if !authenticator.uvSawInteraction {
		t.Fatal("UV command ran before user-verification interaction was recorded")
	}
}

func TestTokenServiceDefaultFlowCanceledUVInteractionSkipsUVCommand(t *testing.T) {
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		NewInteractionBroker(model.NoopEventSink{}, interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
			return model.InteractionResponse{Canceled: true}, nil
		})),
		model.VerificationFlowDefault,
	)

	token, err := tokens.Acquire(
		context.Background(),
		authenticator,
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !model.IsErrorCategory(err, model.ErrorCanceled) {
		t.Fatalf("Acquire error = %v, want canceled runtime error", err)
	}

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}
}

func TestTokenServiceDefaultFlowFallsBackToPINAfterUVFallbackError(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info:  uvTokenInfo(),
		uvErr: ctapdevice.ErrUvNotConfigured,
	}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		model.VerificationFlowDefault,
	)

	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")

	wantKinds := []model.InteractionKind{
		model.InteractionKindUserVerification,
		model.InteractionKindPIN,
	}
	if !slices.Equal(interactionKinds(requests), wantKinds) {
		t.Fatalf("interaction kinds = %v, want %v", interactionKinds(requests), wantKinds)
	}

	if len(authenticator.uvRPIDs) != 1 {
		t.Fatalf("UV token calls = %d, want 1", len(authenticator.uvRPIDs))
	}

	if len(authenticator.pinRPIDs) != 1 {
		t.Fatalf("PIN token calls = %d, want 1", len(authenticator.pinRPIDs))
	}
}

func TestTokenServicePINFlowSkipsUVInteractionAndCommand(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		model.VerificationFlowPIN,
	)

	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}

	if len(requests) != 1 || requests[0].Kind != model.InteractionKindPIN {
		t.Fatalf("interactions = %v, want one PIN interaction", interactionKinds(requests))
	}
}

func TestTokenServiceCachedPINFlowPerformsNoInteraction(t *testing.T) {
	var requests []model.InteractionRequest
	cache := &testTokenCache{}
	handle := secret.New([]byte("cached"))
	cache.SetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}, handle)
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(
		cache,
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		model.VerificationFlowPIN,
	)

	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")

	if len(requests) != 0 {
		t.Fatalf("interactions = %d, want 0", len(requests))
	}

	if len(authenticator.uvRPIDs) != 0 || len(authenticator.pinRPIDs) != 0 {
		t.Fatalf("token commands = UV %d PIN %d, want none", len(authenticator.uvRPIDs), len(authenticator.pinRPIDs))
	}
}

func TestTokenServiceMissingHandlerForUVReturnsInvalidStateBeforeUVCommand(t *testing.T) {
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		NewInteractionBroker(model.NoopEventSink{}, nil),
		model.VerificationFlowDefault,
	)

	token, err := tokens.Acquire(
		context.Background(),
		authenticator,
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !model.IsErrorCategory(err, model.ErrorInvalidState) {
		t.Fatalf("Acquire error = %v, want invalid-state runtime error", err)
	}

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}
}

func recordingInteractionHandler(
	requests *[]model.InteractionRequest,
	response model.InteractionResponse,
) *InteractionBroker {
	return NewInteractionBroker(model.NoopEventSink{}, interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		*requests = append(*requests, req)

		out := response
		if req.Kind != model.InteractionKindPIN {
			out.PIN = nil
		} else if len(out.PIN) != 0 {
			out.PIN = append([]byte(nil), out.PIN...)
		}

		return out, nil
	}))
}

func acquireTokenForTest(
	t *testing.T,
	tokens *TokenService,
	authenticator *recordingTokenDevice,
	permission protocol.Permission,
	rpID string,
) []byte {
	t.Helper()

	token, err := tokens.Acquire(context.Background(), authenticator, permission, rpID)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer secret.Zero(token)

	return slices.Clone(token)
}

func uvTokenInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
		},
	}
}

type testTokenCache struct {
	key    TokenKey
	secret *secret.Handle
}

func (c *testTokenCache) GetToken(key TokenKey) ([]byte, bool, error) {
	if c.secret == nil || c.key != key {
		return nil, false, nil
	}

	token, err := c.secret.Bytes()
	if err != nil {
		return nil, false, err
	}

	return token, true, nil
}

func (c *testTokenCache) SetToken(key TokenKey, token *secret.Handle) {
	if c.secret != nil {
		c.secret.Invalidate()
	}

	c.key = key
	c.secret = token
}

func (c *testTokenCache) InvalidateToken() {
	if c.secret != nil {
		c.secret.Invalidate()
	}

	c.key = TokenKey{}
	c.secret = nil
}

type recordingTokenDevice struct {
	info             protocol.AuthenticatorGetInfoResponse
	uvErr            error
	requests         *[]model.InteractionRequest
	pinRPIDs         []string
	uvRPIDs          []string
	uvSawInteraction bool
}

func (d *recordingTokenDevice) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return d.info
}

func (d *recordingTokenDevice) GetPinUvAuthTokenUsingPIN(
	_ string,
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	d.pinRPIDs = append(d.pinRPIDs, rpID)

	return []byte("pin-token-" + rpID), nil
}

func (d *recordingTokenDevice) GetPinUvAuthTokenUsingUV(_ protocol.Permission, rpID string) ([]byte, error) {
	if d.requests != nil && len(*d.requests) > 0 {
		last := (*d.requests)[len(*d.requests)-1]
		d.uvSawInteraction = last.Kind == model.InteractionKindUserVerification
	}
	d.uvRPIDs = append(d.uvRPIDs, rpID)
	if d.uvErr != nil {
		return nil, d.uvErr
	}

	return []byte("uv-token-" + rpID), nil
}

func interactionKinds(requests []model.InteractionRequest) []model.InteractionKind {
	return lo.Map(requests, func(req model.InteractionRequest, _ int) model.InteractionKind {
		return req.Kind
	})
}
