package secret

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecretHandleBytesReturnsCopy(t *testing.T) {
	secret := New([]byte("token"))

	copy1, err := secret.Bytes()
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}

	copy1[0] = 'X'

	copy2, err := secret.Bytes()
	if err != nil {
		t.Fatalf("read secret again: %v", err)
	}

	if string(copy2) != "token" {
		t.Fatalf("secret returned backing slice, got %q", string(copy2))
	}
}

func TestNewOwnsInputCopy(t *testing.T) {
	input := []byte("token")
	secret := New(input)

	input[0] = 'X'

	got, err := secret.Bytes()
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}

	if string(got) != "token" {
		t.Fatalf("secret retained caller backing slice, got %q", string(got))
	}
}

func TestNewWipesInput(t *testing.T) {
	input := []byte("token")
	secret := New(input)

	if _, err := secret.Bytes(); err != nil {
		t.Fatalf("read secret: %v", err)
	}

	for _, b := range input {
		if b != 0 {
			t.Fatalf("expected caller bytes to be zeroed, got %#v", input)
		}
	}
}

func TestSecretHandleInvalidationZeroesBytes(t *testing.T) {
	secret := New([]byte("token"))
	secret.Invalidate()

	if _, err := secret.Bytes(); err == nil {
		t.Fatal("expected invalidated secret read to fail")
	}

	for _, b := range secret.data {
		if b != 0 {
			t.Fatalf("expected owned bytes to be zeroed, got %#v", secret.data)
		}
	}
}

func TestSecretHandleStringRedactsBytes(t *testing.T) {
	secret := New([]byte("super-secret-token"))

	for _, rendered := range []string{
		secret.String(),
		fmt.Sprint(secret),
		fmt.Sprintf("%#v", secret),
	} {
		if rendered != secretRedacted {
			t.Fatalf("expected redacted string, got %q", rendered)
		}
	}
}

func TestSecretHandleJSONRedactsBytes(t *testing.T) {
	secret := New([]byte("super-secret-token"))

	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}

	if string(encoded) != `"`+secretRedacted+`"` {
		t.Fatalf("expected redacted JSON, got %s", encoded)
	}
}
