package ctapkit

import (
	"context"
	"errors"
	"iter"
	"slices"
	"sync/atomic"
	"testing"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
)

func TestCredentialStoreStateUsesStandalonePCMRToken(t *testing.T) {
	a := &storeStateAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	a.readOnly.Store(true)

	result, err := session.Run(context.Background(), model.CredentialStoreStateOperation{}, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("CredentialStoreState: %v", err)
	}

	output := result.(model.CredentialStoreStateOutput)
	if output.Result.AuthenticatorIdentifierHex != "000102030405060708090a0b0c0d0e0f" ||
		output.Result.CredentialStoreStateHex != "101112131415161718191a1b1c1d1e1f" {
		t.Fatalf("store state = %#v", output.Result)
	}
	wantPermissions := []protocol.Permission{
		protocol.PermissionCredentialManagement,
		protocol.PermissionPersistentCredentialManagementReadOnly,
	}

	if !slices.Equal(a.permissions, wantPermissions) {
		t.Fatalf("token permissions = %v, want %v", a.permissions, wantPermissions)
	}

	if a.stateTokenPermission != protocol.PermissionPersistentCredentialManagementReadOnly {
		t.Fatalf("state token permission = %s, want standalone pcmr", a.stateTokenPermission)
	}
}

func TestCredentialInventoryRejectsMissingMandatoryMetadataTotals(t *testing.T) {
	a := &missingTotalsAuthenticator{stage: "metadata"}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.ListCredentialsOperation{}, userVerificationHandler(t))
	if !failure.IsCode(err, failure.CodeCTAPSpecViolation) {
		t.Fatalf("ListCredentials error = %v, want spec violation", err)
	}
}

func TestEnableLongTouchForResetDryRunAndRefreshFailureCacheEffects(t *testing.T) {
	refreshErr := errors.New("refresh failed after config command")
	a := &longTouchAuthenticator{enableErr: refreshErr}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.Run(context.Background(), model.ConfigStatusOperation{}, nil); err != nil {
		t.Fatalf("prime ConfigStatus: %v", err)
	}
	dryRun, err := session.Run(context.Background(), model.EnableLongTouchForResetOperation{DryRun: true}, nil)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}

	if dryRun.(model.AuthenticatorConfigOutput).Result != nil || a.enableCalls.Load() != 0 {
		t.Fatalf("dry run result/calls = %#v/%d", dryRun, a.enableCalls.Load())
	}

	result, err := session.Run(context.Background(), model.EnableLongTouchForResetOperation{}, nil)
	if !failure.IsCode(err, failure.CodeInternalError) || !errors.Is(err, refreshErr) {
		t.Fatalf("execute error = %v, want refresh failure", err)
	}

	if result.(model.AuthenticatorConfigOutput).Result != nil || a.enableCalls.Load() != 1 {
		t.Fatalf("execute result/calls = %#v/%d", result, a.enableCalls.Load())
	}

	status, err := session.Run(context.Background(), model.ConfigStatusOperation{}, nil)
	if err != nil {
		t.Fatalf("ConfigStatus after refresh failure: %v", err)
	}

	if got := status.(model.ConfigStatusOutput).Report.ResetHints.LongTouchForReset; got != "configured" {
		t.Fatalf("long touch status = %s, want configured", got)
	}

	if a.infoCalls.Load() != 4 {
		t.Fatalf("GetInfo calls = %d, want cache refresh after mutation error", a.infoCalls.Load())
	}
}

func TestEnableLongTouchForResetSuccess(t *testing.T) {
	a := &longTouchAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	result, err := session.Run(context.Background(), model.EnableLongTouchForResetOperation{}, nil)
	if err != nil {
		t.Fatalf("EnableLongTouchForReset: %v", err)
	}

	output := result.(model.AuthenticatorConfigOutput)
	if output.Result == nil || output.Result.State != "configured" || a.enableCalls.Load() != 1 {
		t.Fatalf("output/calls = %#v/%d", output, a.enableCalls.Load())
	}
}

func TestSetMinPINLengthPassesParametersWithoutDefaults(t *testing.T) {
	a := &setMinPINLengthAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	result, err := session.Run(context.Background(), model.SetMinPINLengthOperation{
		MinPINLengthRPIDs:   []string{"example.com"},
		ForceChangePIN:      true,
		PINComplexityPolicy: true,
	}, nil)
	if err != nil {
		t.Fatalf("SetMinPINLength: %v", err)
	}

	if a.params.NewMinPINLength != nil || len(a.params.MinPINLengthRPIDs) != 1 ||
		!a.params.ForceChangePIN || !a.params.PINComplexityPolicy {
		t.Fatalf("upstream params = %#v", a.params)
	}

	output := result.(model.AuthenticatorConfigOutput)
	if output.Result == nil || len(output.Result.MinPINLengthRPIDs) != 1 ||
		!output.Result.ForceChangePIN || !output.Result.PINComplexityPolicy {
		t.Fatalf("result = %#v", output.Result)
	}
}

type storeStateAuthenticator struct {
	contractAuthenticator
	readOnly             atomic.Bool
	permissions          []protocol.Permission
	tokenPermissions     map[string]protocol.Permission
	stateTokenPermission protocol.Permission
}

func (a *storeStateAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	options := map[protocol.Option]bool{
		protocol.OptionCredentialManagement: true,
		protocol.OptionPinUvAuthToken:       true,
		protocol.OptionUserVerification:     true,
	}

	if a.readOnly.Load() {
		options[protocol.OptionCredentialManagementReadOnly] = true
	}

	return protocol.AuthenticatorGetInfoResponse{Options: options}
}

func (a *storeStateAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	permission protocol.Permission,
	_ string,
) ([]byte, error) {
	a.permissions = append(a.permissions, permission)

	if a.tokenPermissions == nil {
		a.tokenPermissions = make(map[string]protocol.Permission)
	}
	token := []byte{byte(permission)}
	a.tokenPermissions[string(token)] = permission

	return token, nil
}

func (a *storeStateAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(0)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
	}, nil
}

func (a *storeStateAuthenticator) GetPersistentCredentialStoreState(
	_ context.Context,
	token []byte,
) (ctapdevice.PersistentCredentialStoreState, error) {
	a.stateTokenPermission = a.tokenPermissions[string(token)]
	var state ctapdevice.PersistentCredentialStoreState
	for index := range state.AuthenticatorIdentifier {
		state.AuthenticatorIdentifier[index] = byte(index)
		state.CredentialStoreState[index] = byte(index + 16)
	}

	return state, nil
}

type longTouchAuthenticator struct {
	contractAuthenticator
	infoCalls   atomic.Int32
	enableCalls atomic.Int32
	enabled     atomic.Bool
	enableErr   error
}

type missingTotalsAuthenticator struct {
	contractAuthenticator
	stage string
}

type setMinPINLengthAuthenticator struct {
	contractAuthenticator
	params protocol.SetMinPINLengthConfigSubCommandParams
}

func (a *setMinPINLengthAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionAuthenticatorConfig: true,
			protocol.OptionSetMinPINLength:     true,
		},
		MinPINLength:                4,
		MaxPINLength:                63,
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength},
	}
}

func (a *setMinPINLengthAuthenticator) SetMinPINLength(
	_ context.Context,
	_ []byte,
	params protocol.SetMinPINLengthConfigSubCommandParams,
) error {
	a.params = params

	return nil
}

func (a *missingTotalsAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionCredentialManagement: true,
		protocol.OptionPinUvAuthToken:       true,
		protocol.OptionUserVerification:     true,
	}}
}

func (a *missingTotalsAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *missingTotalsAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	if a.stage == "metadata" {
		return protocol.AuthenticatorCredentialManagementResponse{}, nil
	}

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(1)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
	}, nil
}

func (a *missingTotalsAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		response := protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "example.com"},
			RPIDHash: []byte("hash"),
		}
		response.TotalRPs = 1
		yield(response, nil)
	}
}

func (a *missingTotalsAuthenticator) EnumerateCredentials(context.Context, []byte, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		response := protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{ID: []byte("user")},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte("credential"),
			},
		}
		response.TotalCredentials = 1
		yield(response, nil)
	}
}

func (a *longTouchAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	a.infoCalls.Add(1)

	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionAuthenticatorConfig: true,
		},
		LongTouchForReset:           new(a.enabled.Load()),
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandEnableLongTouchForReset},
	}
}

func (a *longTouchAuthenticator) EnableLongTouchForReset(context.Context, []byte) error {
	a.enableCalls.Add(1)
	a.enabled.Store(true)

	return a.enableErr
}
