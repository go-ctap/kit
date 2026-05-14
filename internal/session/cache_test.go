package session

import (
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/secret"
	appcredentials "github.com/go-ctap/kit/model/credentials"
)

func TestCacheSetTokenInvalidatesReplacedSecret(t *testing.T) {
	cache := NewCache()
	key := TokenKey{Permission: protocol.PermissionCredentialManagement}
	previous := secret.New([]byte("previous-token"))

	cache.SetToken(key, previous)
	cache.SetToken(key, secret.New([]byte("next-token")))

	if _, err := previous.Bytes(); err == nil {
		t.Fatal("expected replaced token secret to be invalidated")
	}
}

func TestCacheSetTokenInvalidatesExistingSecrets(t *testing.T) {
	cache := NewCache()
	existing := secret.New([]byte("existing-token"))

	cache.SetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}, existing)
	cache.SetToken(
		TokenKey{Permission: protocol.PermissionCredentialManagement, RPID: "example.com"},
		secret.New([]byte("token")),
	)

	if _, err := existing.Bytes(); err == nil {
		t.Fatal("expected existing token secret to be invalidated")
	}

	if _, ok, _ := cache.GetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}); ok {
		t.Fatal("existing token key still cached")
	}

	if _, ok, _ := cache.GetToken(TokenKey{Permission: protocol.PermissionCredentialManagement, RPID: "example.com"}); !ok {
		t.Fatal("token was not cached")
	}
}

func TestCacheInvalidateAllInvalidatesToken(t *testing.T) {
	cache := NewCache()
	key := TokenKey{Permission: protocol.PermissionCredentialManagement}
	token := secret.New([]byte("token"))

	cache.SetToken(key, token)
	cache.InvalidateAll()

	if _, err := token.Bytes(); err == nil {
		t.Fatal("expected cached token secret to be invalidated")
	}
}

func TestCacheInvalidateTokenClearsCurrentToken(t *testing.T) {
	cache := NewCache()
	scopedKey := TokenKey{Permission: protocol.PermissionCredentialManagement, RPID: "example.com"}

	cache.SetToken(scopedKey, secret.New([]byte("scoped-token")))
	cache.InvalidateToken()

	if _, ok, _ := cache.GetToken(scopedKey); ok {
		t.Fatal("scoped token still cached")
	}
}

func TestCacheCredentialClonesMutableCredentialFields(t *testing.T) {
	cache := NewCache()
	report := appcredentials.InventoryReport{
		Groups: []appcredentials.CredentialGroup{
			{
				Credentials: []appcredentials.CredentialRecord{
					{
						CredentialIDHex:      "c05e",
						CredentialTransports: []string{"usb"},
						LargeBlobKey:         []byte{1, 2, 3},
					},
				},
			},
		},
	}

	cache.SetCredential(report)
	report.Groups[0].Credentials[0].LargeBlobKey[0] = 9

	first, ok := cache.Credential()
	if !ok {
		t.Fatal("credential report was not cached")
	}
	if got := first.Groups[0].Credentials[0].LargeBlobKey[0]; got != 1 {
		t.Fatalf("cached key was not cloned on set: first byte = %d, want 1", got)
	}
	if got := first.Groups[0].Credentials[0].CredentialTransports[0]; got != "usb" {
		t.Fatalf("cached transports were not cloned on set: first transport = %q, want usb", got)
	}
	first.Groups[0].Credentials[0].LargeBlobKey[0] = 8
	first.Groups[0].Credentials[0].CredentialTransports[0] = "nfc"

	second, ok := cache.Credential()
	if !ok {
		t.Fatal("credential report was not cached")
	}
	if got := second.Groups[0].Credentials[0].LargeBlobKey[0]; got != 1 {
		t.Fatalf("cached key was not cloned on get: first byte = %d, want 1", got)
	}
	if got := second.Groups[0].Credentials[0].CredentialTransports[0]; got != "usb" {
		t.Fatalf("cached transports were not cloned on get: first transport = %q, want usb", got)
	}
}

func TestCacheInvalidateCredentialsWipesCachedLargeBlobKey(t *testing.T) {
	cache := NewCache()
	cache.SetCredential(appcredentials.InventoryReport{
		Groups: []appcredentials.CredentialGroup{
			{
				Credentials: []appcredentials.CredentialRecord{
					{
						CredentialIDHex: "c05e",
						LargeBlobKey:    []byte{1, 2, 3},
					},
				},
			},
		},
	})

	cached := cache.credentialInventory
	cache.InvalidateCredentials()

	if cached == nil {
		t.Fatal("cached report pointer = nil")
	}
	if got := cached.Groups[0].Credentials[0].LargeBlobKey; got != nil {
		t.Fatalf("cached largeBlobKey = %v, want nil after wipe", got)
	}
}

func TestCacheInvalidateTokenUnlessPermissionPreservesMatchingPermission(t *testing.T) {
	cache := NewCache()
	key := TokenKey{Permission: protocol.PermissionLargeBlobWrite}

	cache.SetToken(key, secret.New([]byte("token")))
	cache.InvalidateTokenUnlessPermission(protocol.PermissionLargeBlobWrite)

	if _, ok, _ := cache.GetToken(key); !ok {
		t.Fatal("matching token was invalidated")
	}
}

func TestCacheInvalidateTokenUnlessPermissionClearsOtherPermission(t *testing.T) {
	cache := NewCache()
	key := TokenKey{Permission: protocol.PermissionCredentialManagement}

	cache.SetToken(key, secret.New([]byte("token")))
	cache.InvalidateTokenUnlessPermission(protocol.PermissionLargeBlobWrite)

	if _, ok, _ := cache.GetToken(key); ok {
		t.Fatal("non-matching token still cached")
	}
}
