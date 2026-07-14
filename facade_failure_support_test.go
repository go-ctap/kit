package ctapkit

import (
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

func requireFailureCode(t *testing.T, err error, code failure.Code) *failure.Error {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}

	typed, ok := err.(*failure.Error)
	if !ok {
		t.Fatalf("error = %T(%v), want *failure.Error", err, err)
	}
	if typed.Code != code {
		t.Fatalf("failure code = %s, want %s (failure = %#v)", typed.Code, code, typed.Failure)
	}
	return typed
}
