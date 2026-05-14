package ctapkit

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"slices"
	"testing"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/transport"
	"github.com/samber/lo"
)

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
				a.deleteErr = &ctaphid.CTAPError{
					Command:    protocol.AuthenticatorCredentialManagement,
					StatusCode: ctaphid.CTAP2_ERR_NO_CREDENTIALS,
				}
			},
			want: appcredentials.ErrCredentialNotFound,
		},
		{
			name:      "update credential store full",
			operation: model.UpdateCredentialUserOperation{CredentialIDHex: "c05e", Name: "updated", NameProvided: true, Confirmed: true},
			setupErr: func(a *credentialMutationTokenAuthenticator) {
				a.updateErr = &ctaphid.CTAPError{
					Command:    protocol.AuthenticatorCredentialManagement,
					StatusCode: ctaphid.CTAP2_ERR_KEY_STORE_FULL,
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

func (a *progressCredentialAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}
}

func (a *progressCredentialAuthenticator) GetPinUvAuthTokenUsingUV(protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *progressCredentialAuthenticator) GetCredsMetadata([]byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             3,
		MaxPossibleRemainingResidentCredentialsCount: 10,
	}, nil
}

func (a *progressCredentialAuthenticator) EnumerateRPs([]byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
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
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	a.tokenRPIDs = append(a.tokenRPIDs, rpID)

	return []byte("token:" + rpID), nil
}

func (a *credentialMutationTokenAuthenticator) GetCredsMetadata(
	[]byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             1,
		MaxPossibleRemainingResidentCredentialsCount: 8,
	}, nil
}

func (a *credentialMutationTokenAuthenticator) EnumerateRPs(
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
	token []byte,
	_ credential.PublicKeyCredentialDescriptor,
) error {
	a.deleteTokens = append(a.deleteTokens, string(token))

	return a.deleteErr
}

func (a *credentialMutationTokenAuthenticator) UpdateUserInformation(
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
