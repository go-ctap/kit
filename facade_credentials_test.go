package ctapkit

import (
	"bytes"
	"context"
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
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
	"github.com/samber/lo"
)

func TestCredentialInventoryReadsFreshStateAndReusesToken(t *testing.T) {
	events := &recordingEventSink{}
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	first := runCredentialList(t, session)
	second := runCredentialList(t, session)
	if got := credentialIDFromInventory(t, first); got != "01" {
		t.Fatalf("first credential ID = %q, want 01", got)
	}

	if got := credentialIDFromInventory(t, second); got != "01" {
		t.Fatalf("cached credential ID = %q, want 01", got)
	}

	a.revision = 2
	refreshed := runCredentialList(t, session)
	if got := credentialIDFromInventory(t, refreshed); got != "02" {
		t.Fatalf("refreshed credential ID = %q, want 02", got)
	}

	if got := a.metadataCalls.Load(); got != 3 {
		t.Fatalf("metadata calls = %d, want 3", got)
	}

	if got := a.tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}

	assertProgressEvents(t, events.Events(), model.OperationStageEnumeratingRPs, [][2]uint64{
		{1, 1},
		{1, 1},
		{1, 1},
	})
	assertProgressEvents(t, events.Events(), model.OperationStageEnumeratingCredentials, [][2]uint64{
		{1, 1},
		{1, 1},
		{1, 1},
	})
}

func TestCredentialInventoryReturnsEmptyReportWithoutEnumeratingRPs(t *testing.T) {
	a := &emptyCredentialAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output := runCredentialList(t, session)
	if output.Summary.ExistingResidentCredentialsCount != 0 {
		t.Fatalf("existing credential count = %d, want 0", output.Summary.ExistingResidentCredentialsCount)
	}

	if output.Summary.TotalCredentials != 0 || len(output.Groups) != 0 {
		t.Fatalf("empty inventory = %#v, want no groups or credentials", output)
	}

	if got := a.rpEnumerations.Load(); got != 0 {
		t.Fatalf("RP enumerations = %d, want 0", got)
	}
}

func TestCredentialInventoryReacquiresRejectedTokenOnce(t *testing.T) {
	a := &rejectedCredentialTokenAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	output := runCredentialList(t, session)
	if output.Summary.ExistingResidentCredentialsCount != 0 {
		t.Fatalf("existing credential count = %d, want 0", output.Summary.ExistingResidentCredentialsCount)
	}

	if got := a.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}

	if got := a.metadataCalls.Load(); got != 2 {
		t.Fatalf("metadata calls = %d, want 2", got)
	}

	if len(a.metadataTokens) != 2 || !bytes.Equal(a.metadataTokens[0], []byte{1}) || !bytes.Equal(a.metadataTokens[1], []byte{2}) {
		t.Fatalf("metadata tokens = %#v, want [[1] [2]]", a.metadataTokens)
	}
}

func TestCredentialInventoryStopsAfterSecondRejectedToken(t *testing.T) {
	a := &rejectedCredentialTokenAuthenticator{rejectEveryToken: true}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !failure.IsCode(err, failure.CodePINUVAuthInvalid) {
		t.Fatalf("ListCredentials error = %v, want %s", err, failure.CodePINUVAuthInvalid)
	}

	if got := a.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}

	if got := a.metadataCalls.Load(); got != 2 {
		t.Fatalf("metadata calls = %d, want 2", got)
	}
}

func TestCredentialMutationUsesInventoryFromSuccessfulRefresh(t *testing.T) {
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_ = runCredentialList(t, session)
	a.revision = 2
	refreshed := runCredentialList(t, session)
	if got := credentialIDFromInventory(t, refreshed); got != "02" {
		t.Fatalf("refreshed credential ID = %q, want 02", got)
	}

	if _, err := session.DeleteCredential(context.Background(), appcredentials.DeleteOperation{
		CredentialIDHex: "02",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	if len(a.deletedCredentialIDs) != 1 || !bytes.Equal(a.deletedCredentialIDs[0], []byte{2}) {
		t.Fatalf("deleted credential IDs = %x, want [02]", a.deletedCredentialIDs)
	}
}

func TestCredentialInventoryProgressEventsIncludeCounts(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractAuthenticator(t, events, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return &progressCredentialAuthenticator{}, nil
	})
	defer func() { _ = session.Close() }()

	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
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

func TestCredentialDeleteReusesUnscopedInventoryGrant(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.DeleteCredential(context.Background(), appcredentials.DeleteOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialMutationToken(t, a.tokenRPIDs, []string{""}, a.deleteTokens, "token:")
}

func TestCredentialUpdateUserUsesTargetWithoutInventory(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	_, err := session.UpdateCredentialUser(context.Background(), appcredentials.UpdateUserOperation{
		Target:       credentialMutationTarget(),
		Name:         "updated",
		NameProvided: true,
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialMutationToken(t, a.tokenRPIDs, []string{""}, a.updateTokens, "token:")
	if got := a.metadataCalls.Load(); got != 0 {
		t.Fatalf("metadata calls = %d, want 0", got)
	}
}

func TestCredentialUpdateUserDryRunUsesTargetWithoutAuthenticatorCommands(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	defer func() { _ = session.Close() }()

	result, err := session.UpdateCredentialUser(context.Background(), appcredentials.UpdateUserOperation{
		Target:       credentialMutationTarget(),
		Name:         "updated",
		NameProvided: true,
		DryRun:       true,
	}, session.operationOptions()...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Preview.Proposed.Name != "updated" {
		t.Fatalf("proposed name = %q, want updated", result.Preview.Proposed.Name)
	}

	if got := a.metadataCalls.Load(); got != 0 {
		t.Fatalf("metadata calls = %d, want 0", got)
	}

	if len(a.tokenRPIDs) != 0 || len(a.updateTokens) != 0 {
		t.Fatalf("dry-run token/update calls = %q/%q, want none", a.tokenRPIDs, a.updateTokens)
	}
}

func credentialMutationTarget() appcredentials.CredentialTarget {
	return appcredentials.CredentialTarget{
		Record: appcredentials.CredentialRecord{
			CredentialIDHex: "c05e",
			CredentialType:  string(credential.PublicKeyCredentialTypePublicKey),
		},
		RP:   appcredentials.RelyingParty{ID: "id.example", Name: "Example"},
		User: appcredentials.UserIdentity{UserIDHex: "75736572", Name: "savely", DisplayName: "Savely"},
	}
}

type progressCredentialAuthenticator struct {
	contractAuthenticator
}

type emptyCredentialAuthenticator struct {
	contractAuthenticator
	rpEnumerations atomic.Int32
}

type rejectedCredentialTokenAuthenticator struct {
	contractAuthenticator
	rejectEveryToken bool
	tokenCalls       atomic.Int32
	metadataCalls    atomic.Int32
	metadataTokens   [][]byte
}

func (a *rejectedCredentialTokenAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}, true
}

func (a *rejectedCredentialTokenAuthenticator) GetPinUvAuthTokenUsingUV(
	context.Context,
	protocol.Permission,
	string,
) ([]byte, error) {
	return []byte{byte(a.tokenCalls.Add(1))}, nil
}

func (a *rejectedCredentialTokenAuthenticator) GetCredsMetadata(
	_ context.Context,
	token []byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls.Add(1)
	a.metadataTokens = append(a.metadataTokens, slices.Clone(token))

	if a.rejectEveryToken || bytes.Equal(token, []byte{1}) {
		return protocol.AuthenticatorCredentialManagementResponse{}, &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorCredentialManagement,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
		}
	}

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(0)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(25)),
	}, nil
}

func (a *emptyCredentialAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}, true
}

func (a *emptyCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *emptyCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(0)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(25)),
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

func (a *refreshCredentialAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}, true
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
		ExistingResidentCredentialsCount:             new(uint(1)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(10)),
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
			TotalCredentials: 1,
		}, nil)
	}
}

func runCredentialList(t *testing.T, session *contractAuthenticatorHandle) appcredentials.InventoryReport {
	t.Helper()

	var opts []OperationOption
	if session.events != nil {
		opts = append(opts, WithEventSink(session.events))
	}
	opts = append(opts, WithInteractionHandler(userVerificationHandler(t)))

	output, err := session.ListCredentials(context.Background(), opts...)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	return *output
}

func credentialIDFromInventory(t *testing.T, output appcredentials.InventoryReport) string {
	t.Helper()

	if len(output.Groups) != 1 || len(output.Groups[0].Credentials) != 1 {
		t.Fatalf("credential inventory = %#v, want one credential", output)
	}

	return output.Groups[0].Credentials[0].CredentialIDHex
}

func (a *progressCredentialAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}, true
}

func (a *progressCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *progressCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(3)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(10)),
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
	credentialManagementReadOnly bool
	metadataCalls                atomic.Int32
	tokenPermissions             []protocol.Permission
	tokenRPIDs                   []string
	deleteTokens                 []string
	updateTokens                 []string
	deleteErr                    error
	updateErr                    error
}

func (a *credentialMutationTokenAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	options := map[protocol.Option]bool{
		protocol.OptionCredentialManagement: true,
		protocol.OptionPinUvAuthToken:       true,
		protocol.OptionUserVerification:     true,
	}

	if a.credentialManagementReadOnly {
		options[protocol.OptionPersistentCredentialManagementReadOnly] = true
	}

	return protocol.AuthenticatorGetInfoResponse{
		Options: options,
	}, true
}

func (a *credentialMutationTokenAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	a.tokenPermissions = append(a.tokenPermissions, permission)
	a.tokenRPIDs = append(a.tokenRPIDs, rpID)

	return []byte("token:" + rpID), nil
}

func (a *credentialMutationTokenAuthenticator) GetCredsMetadata(
	context.Context,
	[]byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls.Add(1)

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(1)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
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
