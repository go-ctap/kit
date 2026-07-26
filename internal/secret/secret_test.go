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

func TestSecretHandleRenderingRedactsBytes(t *testing.T) {
	secret := New([]byte("super-secret-token"))

	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"String", secret.String(), secretRedacted},
		{"Stringer", fmt.Sprint(secret), secretRedacted},
		{"GoStringer", fmt.Sprintf("%#v", secret), secretRedacted},
		{"JSON", string(encoded), `"` + secretRedacted + `"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("rendered secret = %q, want %q", tt.got, tt.want)
			}
		})
	}
}
