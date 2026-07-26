package ctapkit

import (
	"errors"
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

func requireFailureCode(t *testing.T, err error, code failure.Code) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}

	var typed *failure.Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %T(%v), want *failure.Error", err, err)
	}

	if typed.Code != code {
		t.Fatalf("failure code = %s, want %s (failure = %#v)", typed.Code, code, typed.Failure)
	}
}
