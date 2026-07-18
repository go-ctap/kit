package runtime

import (
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/secret"
)

func TestTokenStoreReplacesAndWipesToken(t *testing.T) {
	store := NewTokenStore()
	previous := secret.New([]byte("previous"))
	store.SetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}, previous)

	store.SetToken(
		TokenKey{Permission: protocol.PermissionLargeBlobWrite},
		secret.New([]byte("next")),
	)

	if _, err := previous.Bytes(); err == nil {
		t.Fatal("replaced token was not invalidated")
	}
}

func TestTokenStoreCompositeGrantCoversSubset(t *testing.T) {
	store := NewTokenStore()
	store.SetToken(TokenKey{
		Permission: protocol.PermissionCredentialManagement |
			protocol.PermissionLargeBlobWrite,
	}, secret.New([]byte("token")))

	token, ok, err := store.GetToken(TokenKey{Permission: protocol.PermissionLargeBlobWrite})
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	defer secret.Zero(token)
	if !ok {
		t.Fatal("composite grant did not cover permission subset")
	}
}

func TestTokenStoreInvalidateUnlessPermissionNarrowsGrant(t *testing.T) {
	store := NewTokenStore()
	store.SetToken(TokenKey{
		Permission: protocol.PermissionCredentialManagement |
			protocol.PermissionLargeBlobWrite,
	}, secret.New([]byte("token")))

	store.InvalidateTokenUnlessPermission(protocol.PermissionLargeBlobWrite)

	if _, ok, _ := store.GetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}); ok {
		t.Fatal("removed permission remained available")
	}
	token, ok, err := store.GetToken(TokenKey{Permission: protocol.PermissionLargeBlobWrite})
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	defer secret.Zero(token)
	if !ok {
		t.Fatal("retained permission was invalidated")
	}
}
