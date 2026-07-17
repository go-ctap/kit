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
	"github.com/go-ctap/kit/model/failure"
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

func TestTokenServiceCompositeGrantCoversPermissionSubsets(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(
		&testTokenCache{},
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		model.VerificationFlowDefault,
	)
	permissions := protocol.PermissionCredentialManagement |
		protocol.PermissionLargeBlobWrite

	acquireTokenForTest(t, tokens, authenticator, permissions, "")
	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionLargeBlobWrite, "")
	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")
	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionPersistentCredentialManagementReadOnly, "")

	if got := len(authenticator.uvRPIDs); got != 1 {
		t.Fatalf("UV token calls = %d, want 1", got)
	}
	if got := len(requests); got != 1 {
		t.Fatalf("interactions = %d, want 1", got)
	}
	if got, want := requests[0].Permission, "credentialManagement,largeBlobWrite"; got != want {
		t.Fatalf("interaction permission = %q, want %q", got, want)
	}
}

func TestPermissionLabelFormatsMasksDeterministically(t *testing.T) {
	tests := []struct {
		permission protocol.Permission
		want       string
	}{
		{protocol.PermissionNone, "none"},
		{protocol.PermissionCredentialManagement, "credentialManagement"},
		{
			protocol.PermissionCredentialManagement | protocol.PermissionLargeBlobWrite,
			"credentialManagement,largeBlobWrite",
		},
		{protocol.PermissionPersistentCredentialManagementReadOnly, "persistentCredentialManagementReadOnly"},
		{protocol.Permission(0x80), "unknown(0x80)"},
	}

	for _, tt := range tests {
		if got := permissionLabel(tt.permission); got != tt.want {
			t.Errorf("permissionLabel(%#02x) = %q, want %q", tt.permission, got, tt.want)
		}
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

	if !failure.IsCode(err, failure.CodeInteractionCanceled) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeInteractionCanceled)
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

func TestTokenServicePINInvalidRequestsAnotherPINWithRetryState(t *testing.T) {
	var (
		requests     []model.InteractionRequest
		returnedPINs [][]byte
	)
	powerCycleState := false
	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
		pinErrs: []error{&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
		}},
		pinRetryCounts:  []uint{7, 6},
		pinRetries:      6,
		powerCycleState: &powerCycleState,
	}
	interactions := NewInteractionBroker(
		model.NoopEventSink{},
		interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
			requests = append(requests, req)
			pin := []byte("1234")
			returnedPINs = append(returnedPINs, pin)

			return model.InteractionResponse{PIN: pin}, nil
		}),
	)
	tokens := NewTokenService(&testTokenCache{}, interactions, model.VerificationFlowPIN)

	acquireTokenForTest(t, tokens, authenticator, protocol.PermissionCredentialManagement, "")

	if len(requests) != 2 {
		t.Fatalf("interactions = %d, want 2", len(requests))
	}
	initial := requests[0].PINState
	if initial == nil {
		t.Fatal("initial PIN interaction state = nil")
	}
	if initial.Failure != nil {
		t.Fatalf("initial PIN failure = %#v, want nil", initial.Failure)
	}
	if initial.RetriesRemaining == nil || *initial.RetriesRemaining != 7 {
		t.Fatalf("initial retries remaining = %#v, want 7", initial.RetriesRemaining)
	}
	if initial.PowerCycleState == nil || *initial.PowerCycleState {
		t.Fatalf("initial power cycle state = %#v, want false", initial.PowerCycleState)
	}

	retry := requests[1].PINState
	if retry == nil {
		t.Fatal("retry PIN interaction state = nil")
	}
	if retry.Failure == nil || retry.Failure.Code != failure.CodePINInvalid {
		t.Fatalf("retry failure = %#v, want %s", retry.Failure, failure.CodePINInvalid)
	}
	if retry.Failure.Phase != failure.PhaseTokenAcquisition {
		t.Fatalf("retry failure phase = %s, want %s", retry.Failure.Phase, failure.PhaseTokenAcquisition)
	}
	if retry.Failure.CTAP == nil || retry.Failure.CTAP.StatusCode != uint8(ctaptransport.CTAP2_ERR_PIN_INVALID) {
		t.Fatalf("retry CTAP failure = %#v, want PIN_INVALID provenance", retry.Failure.CTAP)
	}
	if retry.RetriesRemaining == nil || *retry.RetriesRemaining != 6 {
		t.Fatalf("retries remaining = %#v, want 6", retry.RetriesRemaining)
	}
	if retry.PowerCycleState == nil || *retry.PowerCycleState {
		t.Fatalf("power cycle state = %#v, want false", retry.PowerCycleState)
	}
	if authenticator.pinRetriesCalls != 2 {
		t.Fatalf("GetPINRetries calls = %d, want 2", authenticator.pinRetriesCalls)
	}
	if len(authenticator.pinRPIDs) != 2 {
		t.Fatalf("PIN token calls = %d, want 2", len(authenticator.pinRPIDs))
	}
	for _, pin := range returnedPINs {
		if !slices.Equal(pin, []byte{0, 0, 0, 0}) {
			t.Fatalf("handler-owned PIN was not wiped: %#v", pin)
		}
	}
}

func TestTokenServicePINBlockedDoesNotRequestAnotherPIN(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
		pinErrs: []error{&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_BLOCKED,
		}},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		model.VerificationFlowPIN,
	)

	token, err := tokens.Acquire(context.Background(), authenticator, protocol.PermissionCredentialManagement, "")
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}
	if !failure.IsCode(err, failure.CodePINBlocked) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodePINBlocked)
	}
	if len(requests) != 1 {
		t.Fatalf("interactions = %d, want 1", len(requests))
	}
	if authenticator.pinRetriesCalls != 1 {
		t.Fatalf("GetPINRetries calls = %d, want 1", authenticator.pinRetriesCalls)
	}
}

func TestTokenServicePINRetriesFailureStopsRetryFlow(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
		pinErrs: []error{&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
		}},
		pinRetryCounts: []uint{7},
		pinRetriesErrs: []error{
			nil,
			&ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorClientPIN,
				StatusCode: ctaptransport.CTAP1_ERR_TIMEOUT,
			},
		},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		model.VerificationFlowPIN,
	)

	token, err := tokens.Acquire(context.Background(), authenticator, protocol.PermissionCredentialManagement, "")
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}
	if !failure.IsCode(err, failure.CodeAuthenticatorTimeout) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeAuthenticatorTimeout)
	}
	snapshot := failure.Snapshot(err)
	if snapshot.Phase != failure.PhaseTokenAcquisition {
		t.Fatalf("failure phase = %s, want %s", snapshot.Phase, failure.PhaseTokenAcquisition)
	}
	if snapshot.CTAP == nil || snapshot.CTAP.SubCommand != "getPINRetries" {
		t.Fatalf("CTAP detail = %#v, want getPINRetries provenance", snapshot.CTAP)
	}
	if len(requests) != 1 {
		t.Fatalf("interactions = %d, want 1", len(requests))
	}
	if authenticator.pinRetriesCalls != 2 {
		t.Fatalf("GetPINRetries calls = %d, want 2", authenticator.pinRetriesCalls)
	}
}

func TestTokenServiceDelegatesPINValidationToAuthenticator(t *testing.T) {
	var requests []model.InteractionRequest
	validationErr := errors.New("pin rejected by ctap")
	authenticator := &recordingTokenDevice{
		info:    uvTokenInfo(),
		pinErrs: []error{validationErr},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("123")}),
		model.VerificationFlowPIN,
	)

	token, err := tokens.Acquire(context.Background(), authenticator, protocol.PermissionCredentialManagement, "")
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}
	if !failure.IsCode(err, failure.CodeInternalError) || !errors.Is(err, validationErr) {
		t.Fatalf("Acquire error = %v, want delegated validation error", err)
	}
	if len(authenticator.pinRPIDs) != 1 {
		t.Fatalf("PIN token calls = %d, want 1", len(authenticator.pinRPIDs))
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

func TestTokenServiceUseReacquiresRejectedTokenOnce(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(
		&testTokenCache{},
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		model.VerificationFlowDefault,
	)

	var usedTokens [][]byte
	err := tokens.Use(
		context.Background(),
		authenticator,
		protocol.PermissionCredentialManagement,
		"",
		func(token []byte) error {
			usedTokens = append(usedTokens, token)
			if len(usedTokens) == 1 {
				return &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorCredentialManagement,
					StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
				}
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
	if got := len(requests); got != 2 {
		t.Fatalf("interactions = %d, want 2", got)
	}
	if want := []string{"", ""}; !slices.Equal(authenticator.uvRPIDs, want) {
		t.Fatalf("UV token rpIds = %v, want %v", authenticator.uvRPIDs, want)
	}
	for index, token := range usedTokens {
		if !slices.Equal(token, make([]byte, len(token))) {
			t.Fatalf("used token %d was not zeroed", index)
		}
	}
}

func TestTokenServiceUseKeepsTokenAfterOtherConsumerFailures(t *testing.T) {
	tests := []struct {
		name   string
		status ctaptransport.StatusCode
	}{
		{
			name:   "unauthorized permission",
			status: ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION,
		},
		{
			name:   "blocked auth",
			status: ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED,
		},
		{
			name:   "required token",
			status: ctaptransport.CTAP2_ERR_PUAT_REQUIRED,
		},
		{
			name:   "unrelated error",
			status: ctaptransport.CTAP1_ERR_TIMEOUT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &testTokenCache{}
			key := TokenKey{Permission: protocol.PermissionCredentialManagement}
			cache.SetToken(key, secret.New([]byte("cached-token")))
			tokens := NewTokenService(cache, nil, model.VerificationFlowDefault)
			consumerErr := &ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorCredentialManagement,
				StatusCode: tt.status,
			}

			uses := 0
			err := tokens.Use(
				context.Background(),
				&recordingTokenDevice{info: uvTokenInfo()},
				protocol.PermissionCredentialManagement,
				"",
				func([]byte) error {
					uses++

					return consumerErr
				},
			)
			if !errors.Is(err, consumerErr) {
				t.Fatalf("Use error = %v, want consumer error", err)
			}
			if uses != 1 {
				t.Fatalf("token uses = %d, want 1", uses)
			}
			if _, present, _ := cache.GetToken(key); !present {
				t.Fatal("cached token was invalidated")
			}
		})
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

	if !failure.IsCode(err, failure.CodeInteractionHandlerRequired) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeInteractionHandlerRequired)
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
	if c.secret == nil || !c.key.Covers(key) {
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
	pinErrs          []error
	pinRetryCounts   []uint
	pinRetries       uint
	powerCycleState  *bool
	pinRetriesErrs   []error
	pinRetriesCalls  int
	requests         *[]model.InteractionRequest
	pinRPIDs         []string
	uvRPIDs          []string
	uvSawInteraction bool
}

func (d *recordingTokenDevice) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return d.info
}

func (d *recordingTokenDevice) GetPinUvAuthTokenUsingPIN(
	_ context.Context,
	_ string,
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	d.pinRPIDs = append(d.pinRPIDs, rpID)
	call := len(d.pinRPIDs) - 1
	if call < len(d.pinErrs) && d.pinErrs[call] != nil {
		return nil, d.pinErrs[call]
	}

	return []byte("pin-token-" + rpID), nil
}

func (d *recordingTokenDevice) GetPinUvAuthTokenUsingUV(_ context.Context, _ protocol.Permission, rpID string) ([]byte, error) {
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

func (d *recordingTokenDevice) GetPINRetries(context.Context) (uint, *bool, error) {
	call := d.pinRetriesCalls
	d.pinRetriesCalls++
	retries := d.pinRetries
	if call < len(d.pinRetryCounts) {
		retries = d.pinRetryCounts[call]
	}
	var err error
	if call < len(d.pinRetriesErrs) {
		err = d.pinRetriesErrs[call]
	}

	return retries, d.powerCycleState, err
}

func interactionKinds(requests []model.InteractionRequest) []model.InteractionKind {
	return lo.Map(requests, func(req model.InteractionRequest, _ int) model.InteractionKind {
		return req.Kind
	})
}
