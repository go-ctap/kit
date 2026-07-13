package ctapkit

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/transport"
	"github.com/samber/lo"
)

func TestCredentialInventoryRefreshBypassesCacheAndReusesToken(t *testing.T) {
	events := &recordingEventSink{}
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	first := runCredentialList(t, session, model.ListCredentialsOperation{})
	second := runCredentialList(t, session, model.ListCredentialsOperation{})
	if got := credentialIDFromInventory(t, first); got != "01" {
		t.Fatalf("first credential ID = %q, want 01", got)
	}
	if got := credentialIDFromInventory(t, second); got != "01" {
		t.Fatalf("cached credential ID = %q, want 01", got)
	}

	a.revision = 2
	refreshed := runCredentialList(t, session, model.ListCredentialsOperation{Refresh: true})
	if got := credentialIDFromInventory(t, refreshed); got != "02" {
		t.Fatalf("refreshed credential ID = %q, want 02", got)
	}
	if got := a.metadataCalls.Load(); got != 2 {
		t.Fatalf("metadata calls = %d, want 2", got)
	}
	if got := a.tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}

	assertProgressEvents(t, events.Events(), model.OperationStageEnumeratingRPs, [][2]uint64{
		{1, 1},
		{1, 1},
	})
	assertProgressEvents(t, events.Events(), model.OperationStageEnumeratingCredentials, [][2]uint64{
		{1, 1},
		{1, 1},
	})
}

func TestCredentialInventoryReturnsEmptyReportWithoutEnumeratingRPs(t *testing.T) {
	a := &emptyCredentialAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output := runCredentialList(t, session, model.ListCredentialsOperation{})
	if output.Report.Summary.ExistingResidentCredentialsCount != 0 {
		t.Fatalf("existing credential count = %d, want 0", output.Report.Summary.ExistingResidentCredentialsCount)
	}
	if output.Report.Summary.TotalCredentials != 0 || len(output.Report.Groups) != 0 {
		t.Fatalf("empty inventory = %#v, want no groups or credentials", output.Report)
	}
	if got := a.rpEnumerations.Load(); got != 0 {
		t.Fatalf("RP enumerations = %d, want 0", got)
	}
}

func TestCredentialInventoryFailedRefreshPreservesLastKnownGoodCache(t *testing.T) {
	tests := []struct {
		name       string
		refreshErr error
	}{
		{name: "device failure", refreshErr: errors.New("refresh failed")},
		{name: "cancellation", refreshErr: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &refreshCredentialAuthenticator{revision: 1}
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			initial := runCredentialList(t, session, model.ListCredentialsOperation{})
			if got := credentialIDFromInventory(t, initial); got != "01" {
				t.Fatalf("initial credential ID = %q, want 01", got)
			}

			a.revision = 2
			a.metadataErr = tt.refreshErr
			if _, err := session.Run(
				context.Background(),
				model.ListCredentialsOperation{Refresh: true},
				userVerificationHandler(t),
			); err == nil {
				t.Fatal("refresh error = nil")
			}

			cached := runCredentialList(t, session, model.ListCredentialsOperation{})
			if got := credentialIDFromInventory(t, cached); got != "01" {
				t.Fatalf("credential ID after failed refresh = %q, want cached 01", got)
			}
			if got := a.metadataCalls.Load(); got != 2 {
				t.Fatalf("metadata calls = %d, want 2", got)
			}
			if got := a.tokenCalls.Load(); got != 1 {
				t.Fatalf("token calls = %d, want 1", got)
			}
		})
	}
}

func TestCredentialInventoryCanceledContextDuringRefreshPreservesLastKnownGoodCache(t *testing.T) {
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	initial := runCredentialList(t, session, model.ListCredentialsOperation{})
	if got := credentialIDFromInventory(t, initial); got != "01" {
		t.Fatalf("initial credential ID = %q, want 01", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.revision = 2
	a.cancelEnumeration = cancel
	if _, err := session.Run(
		ctx,
		model.ListCredentialsOperation{Refresh: true},
		userVerificationHandler(t),
	); !model.IsErrorCategory(err, model.ErrorCanceled) {
		t.Fatalf("refresh error = %v, want canceled", err)
	}
	a.cancelEnumeration = nil

	cached := runCredentialList(t, session, model.ListCredentialsOperation{})
	if got := credentialIDFromInventory(t, cached); got != "01" {
		t.Fatalf("credential ID after canceled refresh = %q, want cached 01", got)
	}
	if got := a.metadataCalls.Load(); got != 2 {
		t.Fatalf("metadata calls = %d, want 2", got)
	}
}

func TestCredentialMutationUsesInventoryFromSuccessfulRefresh(t *testing.T) {
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_ = runCredentialList(t, session, model.ListCredentialsOperation{})
	a.revision = 2
	refreshed := runCredentialList(t, session, model.ListCredentialsOperation{Refresh: true})
	if got := credentialIDFromInventory(t, refreshed); got != "02" {
		t.Fatalf("refreshed credential ID = %q, want 02", got)
	}

	if _, err := session.Run(context.Background(), model.DeleteCredentialOperation{
		CredentialIDHex: "02",
		Confirmed:       true,
	}, userVerificationHandler(t)); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if len(a.deletedCredentialIDs) != 1 || !bytes.Equal(a.deletedCredentialIDs[0], []byte{2}) {
		t.Fatalf("deleted credential IDs = %x, want [02]", a.deletedCredentialIDs)
	}
}

func TestCredentialInventoryRefreshInvalidatesLargeBlobListCache(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.Run(context.Background(), model.ListLargeBlobsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("first ListLargeBlobs: %v", err)
	}
	if _, err := session.Run(
		context.Background(),
		model.ListCredentialsOperation{Refresh: true},
		userVerificationHandler(t),
	); err != nil {
		t.Fatalf("refresh ListCredentials: %v", err)
	}
	if _, err := session.Run(context.Background(), model.ListLargeBlobsOperation{}, userVerificationHandler(t)); err != nil {
		t.Fatalf("second ListLargeBlobs: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 2 {
		t.Fatalf("RP enumerations = %d, want 2", got)
	}
	if got := a.credentialEnumerations.Load(); got != 2 {
		t.Fatalf("credential enumerations = %d, want 2", got)
	}
	if got := a.largeBlobReads.Load(); got != 2 {
		t.Fatalf("large blob reads = %d, want 2", got)
	}
}

func TestCredentialInventoryProgressEventsIncludeCounts(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractSession(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return &progressCredentialAuthenticator{}, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.Run(
		context.Background(),
		model.ListCredentialsOperation{},
		userVerificationHandler(t),
	); err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertProgressEvents(t, events.Events(), model.OperationStageEnumeratingRPs, [][2]uint64{
		{1, 2},
		{2, 2},
	})
	assertProgressEvents(t, events.Events(), model.OperationStageEnumeratingCredentials, [][2]uint64{
		{1, 3},
		{2, 3},
		{3, 3},
	})
}

func TestCredentialDeleteUsesUnscopedMutationPermissionsByDefault(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.DeleteCredentialOperation{
		CredentialIDHex: "c05e",
		Confirmed:       true,
	}, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialMutationToken(t, a.tokenRPIDs, []string{""}, a.deleteTokens, "token:")
}

func TestCredentialDeleteUsesScopedMutationPermissionsWhenStrict(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractSessionWithOptions(
		t,
		nil,
		func(context.Context, transport.Mode, string) (authenticator.Device, error) {
			return a, nil
		},
		WithStrictPermissions(),
	)
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.DeleteCredentialOperation{
		CredentialIDHex: "c05e",
		Confirmed:       true,
	}, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialMutationToken(
		t,
		a.tokenRPIDs,
		[]string{"", "id.example"},
		a.deleteTokens,
		"token:id.example",
	)
}

func TestCredentialUpdateUserUsesUnscopedMutationPermissionsByDefault(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.UpdateCredentialUserOperation{
		CredentialIDHex: "c05e",
		Name:            "updated",
		NameProvided:    true,
		Confirmed:       true,
	}, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialMutationToken(t, a.tokenRPIDs, []string{""}, a.updateTokens, "token:")
}

func TestCredentialUpdateUserUsesScopedMutationPermissionsWhenStrict(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractSessionWithOptions(
		t,
		nil,
		func(context.Context, transport.Mode, string) (authenticator.Device, error) {
			return a, nil
		},
		WithStrictPermissions(),
	)
	defer func() { _ = session.Close() }()

	_, err := session.Run(context.Background(), model.UpdateCredentialUserOperation{
		CredentialIDHex: "c05e",
		Name:            "updated",
		NameProvided:    true,
		Confirmed:       true,
	}, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialMutationToken(
		t,
		a.tokenRPIDs,
		[]string{"", "id.example"},
		a.updateTokens,
		"token:id.example",
	)
}

func TestCredentialMutationCTAPStatusMapsSentinel(t *testing.T) {
	tests := []struct {
		name      string
		operation model.Operation
		setupErr  func(*credentialMutationTokenAuthenticator)
		want      error
	}{
		{
			name:      "delete missing credential",
			operation: model.DeleteCredentialOperation{CredentialIDHex: "c05e", Confirmed: true},
			setupErr: func(a *credentialMutationTokenAuthenticator) {
				a.deleteErr = &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorCredentialManagement,
					StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
				}
			},
			want: appcredentials.ErrCredentialNotFound,
		},
		{
			name:      "update credential store full",
			operation: model.UpdateCredentialUserOperation{CredentialIDHex: "c05e", Name: "updated", NameProvided: true, Confirmed: true},
			setupErr: func(a *credentialMutationTokenAuthenticator) {
				a.updateErr = &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorCredentialManagement,
					StatusCode: ctaptransport.CTAP2_ERR_KEY_STORE_FULL,
				}
			},
			want: appcredentials.ErrCredentialStoreFull,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &credentialMutationTokenAuthenticator{}
			tt.setupErr(a)
			session := openContractSession(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
				return a, nil
			})
			defer func() { _ = session.Close() }()

			_, err := session.Run(context.Background(), tt.operation, userVerificationHandler(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Run error = %v, want sentinel %v", err, tt.want)
			}
			if !model.IsErrorCategory(err, model.ErrorInvalidState) {
				t.Fatalf("Run category = %v, want invalid-state", err)
			}
		})
	}
}

type progressCredentialAuthenticator struct {
	contractAuthenticator
}

type emptyCredentialAuthenticator struct {
	contractAuthenticator
	rpEnumerations atomic.Int32
}

func (a *emptyCredentialAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}
}

func (a *emptyCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *emptyCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		MaxPossibleRemainingResidentCredentialsCount: 25,
	}, nil
}

func (a *emptyCredentialAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	a.rpEnumerations.Add(1)
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{}, &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorCredentialManagement,
			StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
		})
	}
}

type refreshCredentialAuthenticator struct {
	contractAuthenticator
	revision             byte
	metadataErr          error
	cancelEnumeration    context.CancelFunc
	deletedCredentialIDs [][]byte
	tokenCalls           atomic.Int32
	metadataCalls        atomic.Int32
}

func (a *refreshCredentialAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}
}

func (a *refreshCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	a.tokenCalls.Add(1)

	return []byte("token"), nil
}

func (a *refreshCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls.Add(1)
	if a.metadataErr != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, a.metadataErr
	}

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             1,
		MaxPossibleRemainingResidentCredentialsCount: 10,
	}, nil
}

func (a *refreshCredentialAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if a.cancelEnumeration != nil {
			a.cancelEnumeration()
		}
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *refreshCredentialAuthenticator) DeleteCredential(
	_ context.Context,
	_ []byte,
	descriptor credential.PublicKeyCredentialDescriptor,
) error {
	a.deletedCredentialIDs = append(a.deletedCredentialIDs, slices.Clone(descriptor.ID))
	return nil
}

func (a *refreshCredentialAuthenticator) EnumerateCredentials(
	context.Context,
	[]byte,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "user",
				DisplayName: "User",
			},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte{a.revision},
			},
		}, nil)
	}
}

func runCredentialList(t *testing.T, session *Session, operation model.ListCredentialsOperation) model.CredentialsOutput {
	t.Helper()

	result, err := session.Run(context.Background(), operation, userVerificationHandler(t))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	output, ok := result.(model.CredentialsOutput)
	if !ok {
		t.Fatalf("ListCredentials output = %T, want CredentialsOutput", result)
	}

	return output
}

func credentialIDFromInventory(t *testing.T, output model.CredentialsOutput) string {
	t.Helper()

	if len(output.Report.Groups) != 1 || len(output.Report.Groups[0].Credentials) != 1 {
		t.Fatalf("credential inventory = %#v, want one credential", output.Report)
	}

	return output.Report.Groups[0].Credentials[0].CredentialIDHex
}

func (a *progressCredentialAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}
}

func (a *progressCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *progressCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             3,
		MaxPossibleRemainingResidentCredentialsCount: 10,
	}, nil
}

func (a *progressCredentialAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if !yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "alpha.example", Name: "Alpha"},
			RPIDHash: []byte("alpha-rp-hash"),
			TotalRPs: 2,
		}, nil) {
			return
		}

		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "beta.example", Name: "Beta"},
			RPIDHash: []byte("beta-rp-hash"),
		}, nil)
	}
}

func (a *progressCredentialAuthenticator) EnumerateCredentials(
	_ context.Context,
	_ []byte,
	rpIDHash []byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if bytes.Equal(rpIDHash, []byte("alpha-rp-hash")) {
			if !yield(progressCredentialResponse("alpha-user-1", []byte{0xa1}, 2), nil) {
				return
			}

			yield(progressCredentialResponse("alpha-user-2", []byte{0xa2}, 0), nil)

			return
		}

		yield(progressCredentialResponse("beta-user-1", []byte{0xb1}, 1), nil)
	}
}

func progressCredentialResponse(
	userName string,
	credentialID []byte,
	totalCredentials uint,
) protocol.AuthenticatorCredentialManagementResponse {
	return protocol.AuthenticatorCredentialManagementResponse{
		User: credential.PublicKeyCredentialUserEntity{
			ID:          []byte(userName),
			Name:        userName,
			DisplayName: userName,
		},
		CredentialID: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   credentialID,
		},
		TotalCredentials: totalCredentials,
	}
}

type credentialMutationTokenAuthenticator struct {
	contractAuthenticator
	tokenRPIDs   []string
	deleteTokens []string
	updateTokens []string
	deleteErr    error
	updateErr    error
}

func (a *credentialMutationTokenAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}
}

func (a *credentialMutationTokenAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	a.tokenRPIDs = append(a.tokenRPIDs, rpID)

	return []byte("token:" + rpID), nil
}

func (a *credentialMutationTokenAuthenticator) GetCredsMetadata(
	context.Context,
	[]byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             1,
		MaxPossibleRemainingResidentCredentialsCount: 8,
	}, nil
}

func (a *credentialMutationTokenAuthenticator) EnumerateRPs(
	context.Context,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "id.example", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *credentialMutationTokenAuthenticator) EnumerateCredentials(
	context.Context,
	[]byte,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "savely",
				DisplayName: "Savely",
			},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte{0xc0, 0x5e},
			},
			TotalCredentials: 1,
		}, nil)
	}
}

func (a *credentialMutationTokenAuthenticator) DeleteCredential(
	_ context.Context,
	token []byte,
	_ credential.PublicKeyCredentialDescriptor,
) error {
	a.deleteTokens = append(a.deleteTokens, string(token))

	return a.deleteErr
}

func (a *credentialMutationTokenAuthenticator) UpdateUserInformation(
	_ context.Context,
	token []byte,
	_ credential.PublicKeyCredentialDescriptor,
	_ credential.PublicKeyCredentialUserEntity,
) error {
	a.updateTokens = append(a.updateTokens, string(token))

	return a.updateErr
}

func assertCredentialMutationToken(
	t *testing.T,
	gotRPIDs []string,
	wantRPIDs []string,
	gotTokens []string,
	wantToken string,
) {
	t.Helper()

	if !slices.Equal(gotRPIDs, wantRPIDs) {
		t.Fatalf("token rpIds = %q, want %q", gotRPIDs, wantRPIDs)
	}

	if !slices.Equal(gotTokens, []string{wantToken}) {
		t.Fatalf("mutation tokens = %q, want [%q]", gotTokens, wantToken)
	}
}

func assertProgressEvents(
	t *testing.T,
	events []model.OperationEvent,
	stage model.OperationStage,
	want [][2]uint64,
) {
	t.Helper()

	got := lo.FilterMap(events, func(event model.OperationEvent, _ int) ([2]uint64, bool) {
		if event.Stage != stage {
			return [2]uint64{}, false
		}

		if event.Completed == nil || event.Total == nil {
			t.Fatalf("%s event omitted progress counts: %#v", stage, event)
		}

		return [2]uint64{*event.Completed, *event.Total}, true
	})

	if len(got) != len(want) {
		t.Fatalf("%s progress events = %v, want %v", stage, got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s progress events = %v, want %v", stage, got, want)
		}
	}
}
