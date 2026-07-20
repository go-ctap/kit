package ctapkit

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
	"github.com/go-ctap/kit/transport"
)

func TestAuthenticatorMutationsInvalidateRetainedLargeBlobSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contractAuthenticatorHandle, InteractionHandler) error
	}{
		{
			name: "delete credential",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.DeleteCredential(t.Context(), appcredentials.DeleteOperation{
					CredentialIDHex: "c05e",
				}, session.operationOptions(WithInteractionHandler(handler))...)

				return err
			},
		},
		{
			name: "update credential user",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.UpdateCredentialUser(t.Context(), appcredentials.UpdateUserOperation{
					Target:       credentialMutationTarget(),
					Name:         "updated",
					NameProvided: true,
				}, session.operationOptions(WithInteractionHandler(handler))...)

				return err
			},
		},
		{
			name: "make credential",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.MakeCredential(
					t.Context(),
					sampleMakeCredentialOperation(false),
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
		{
			name: "write large blob through WebAuthn",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.GetAssertion(t.Context(), largeBlobWriteAssertionOperation(false),
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
		{
			name: "factory reset",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.ResetFactory(t.Context(), appconfig.ResetFactoryOperation{},
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, session, handler := openStateEffectAuthenticator(t)
			primeLargeBlobSnapshot(t, session, handler)

			if err := tt.mutate(session, handler); err != nil {
				t.Fatalf("mutate: %v", err)
			}

			assertNextLargeBlobReadRefreshes(t, a, session, handler)
		})
	}
}

func TestMutationDryRunsKeepRetainedLargeBlobSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contractAuthenticatorHandle, InteractionHandler) error
	}{
		{
			name: "delete credential",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.DeleteCredential(t.Context(), appcredentials.DeleteOperation{
					CredentialIDHex: "c05e",
					DryRun:          true,
				}, session.operationOptions(WithInteractionHandler(handler))...)

				return err
			},
		},
		{
			name: "update credential user",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.UpdateCredentialUser(t.Context(), appcredentials.UpdateUserOperation{
					Target:       credentialMutationTarget(),
					Name:         "updated",
					NameProvided: true,
					DryRun:       true,
				}, session.operationOptions(WithInteractionHandler(handler))...)

				return err
			},
		},
		{
			name: "make credential",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.MakeCredential(
					t.Context(),
					sampleMakeCredentialOperation(true),
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
		{
			name: "write large blob through WebAuthn",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.GetAssertion(t.Context(), largeBlobWriteAssertionOperation(true),
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
		{
			name: "factory reset",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.ResetFactory(t.Context(), appconfig.ResetFactoryOperation{DryRun: true},
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, session, handler := openStateEffectAuthenticator(t)
			primeLargeBlobSnapshot(t, session, handler)

			if err := tt.mutate(session, handler); err != nil {
				t.Fatalf("dry run: %v", err)
			}

			assertNextLargeBlobReadUsesSnapshot(t, a, session, handler)
		})
	}
}

func TestFailedMutationInvalidatesRetainedLargeBlobSnapshot(t *testing.T) {
	a, session, handler := openStateEffectAuthenticator(t)
	primeLargeBlobSnapshot(t, session, handler)

	a.deleteErr = errors.New("delete result unknown")
	_, err := session.DeleteCredential(t.Context(), appcredentials.DeleteOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err == nil {
		t.Fatal("DeleteCredential error = nil")
	}

	assertNextLargeBlobReadRefreshes(t, a, session, handler)
}

func TestFailedLargeBlobWriteInvalidatesRetainedSnapshot(t *testing.T) {
	a, session, handler := openStateEffectAuthenticator(t)
	primeLargeBlobSnapshot(t, session, handler)

	a.setErr = errors.New("large blob write result unknown")
	_, err := session.WriteLargeBlob(t.Context(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("updated"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err == nil {
		t.Fatal("WriteLargeBlob error = nil")
	}

	assertNextLargeBlobReadRefreshes(t, a, session, handler)
}

func openStateEffectAuthenticator(
	t *testing.T,
) (*stateEffectAuthenticator, *contractAuthenticatorHandle, InteractionHandler) {
	t.Helper()

	a := &stateEffectAuthenticator{}
	session := openContractAuthenticator(t, nil, func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		return a, nil
	})
	t.Cleanup(func() { _ = session.Close() })
	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		return model.InteractionResponse{}, nil
	})

	return a, session, handler
}

func primeLargeBlobSnapshot(
	t *testing.T,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	_, err := session.ListLargeBlobs(
		t.Context(),
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	if err != nil {
		t.Fatalf("ListLargeBlobs: %v", err)
	}
}

func assertNextLargeBlobReadRefreshes(
	t *testing.T,
	a *stateEffectAuthenticator,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	credentialReads := a.credentialEnumerations.Load()
	largeBlobReads := a.largeBlobReads.Load()
	readLargeBlob(t, session, handler)

	if got := a.credentialEnumerations.Load(); got != credentialReads+1 {
		t.Fatalf("credential enumerations = %d, want %d", got, credentialReads+1)
	}
	if got := a.largeBlobReads.Load(); got != largeBlobReads+1 {
		t.Fatalf("large blob reads = %d, want %d", got, largeBlobReads+1)
	}
}

func assertNextLargeBlobReadUsesSnapshot(
	t *testing.T,
	a *stateEffectAuthenticator,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	credentialReads := a.credentialEnumerations.Load()
	largeBlobReads := a.largeBlobReads.Load()
	readLargeBlob(t, session, handler)

	if got := a.credentialEnumerations.Load(); got != credentialReads {
		t.Fatalf("credential enumerations = %d, want %d", got, credentialReads)
	}
	if got := a.largeBlobReads.Load(); got != largeBlobReads {
		t.Fatalf("large blob reads = %d, want %d", got, largeBlobReads)
	}
}

func readLargeBlob(
	t *testing.T,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	_, err := session.ReadLargeBlob(t.Context(), applargeblobs.ReadOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("ReadLargeBlob: %v", err)
	}
}

func largeBlobWriteAssertionOperation(dryRun bool) appwebauthn.GetAssertionOperation {
	return appwebauthn.GetAssertionOperation{
		GetAssertionInput: appwebauthn.GetAssertionInput{
			RPID:           "id.example",
			ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
			Extensions: &ctapwebauthn.GetAuthenticationExtensionsClientInputs{
				LargeBlobInputs: &ctapwebauthn.LargeBlobInputs{
					LargeBlob: ctapwebauthn.AuthenticationExtensionsLargeBlobInputs{
						Write: []byte{},
					},
				},
			},
		},
		DryRun: dryRun,
	}
}

type stateEffectAuthenticator struct {
	largeBlobWriteEventAuthenticator
	deleteErr error
}

func (a *stateEffectAuthenticator) DeleteCredential(
	context.Context,
	[]byte,
	credential.PublicKeyCredentialDescriptor,
) error {
	return a.deleteErr
}

func (a *stateEffectAuthenticator) UpdateUserInformation(
	context.Context,
	[]byte,
	credential.PublicKeyCredentialDescriptor,
	credential.PublicKeyCredentialUserEntity,
) error {
	return nil
}

func (a *stateEffectAuthenticator) Reset(context.Context) error {
	return nil
}

func (a *stateEffectAuthenticator) MakeCredential(
	context.Context,
	[]byte,
	[]byte,
	credential.PublicKeyCredentialRpEntity,
	credential.PublicKeyCredentialUserEntity,
	[]credential.PublicKeyCredentialParameters,
	[]credential.PublicKeyCredentialDescriptor,
	*ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
	uint,
	[]attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return sampleMakeCredentialResponse(), nil
}

func (a *stateEffectAuthenticator) GetAssertion(
	context.Context,
	[]byte,
	string,
	[]byte,
	[]credential.PublicKeyCredentialDescriptor,
	*ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		yield(sampleAssertionResponse([]byte{0xc0, 0x5e}, []byte{0xaa}, []byte("user"), 1), nil)
	}
}
