package logging

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

func TestFinishAddsBoundedTransportErrorMessage(t *testing.T) {
	err := failure.Wrap(
		failure.CodeTransportFailure,
		&ctaptransport.IOError{Operation: ctaptransport.IORead, Err: io.ErrClosedPipe},
	)

	entry := Finish(model.LogEntry{}, time.Now(), err)
	if entry.ErrorMessage != "transport read: io: read/write on closed pipe" {
		t.Fatalf("error message = %q", entry.ErrorMessage)
	}

	longErr := failure.Wrap(failure.CodeTransportFailure, errors.New(strings.Repeat("x", previewBytes+100)))
	entry = Finish(model.LogEntry{}, time.Now(), longErr)
	if len(entry.ErrorMessage) != previewBytes {
		t.Fatalf("error message bytes = %d, want %d", len(entry.ErrorMessage), previewBytes)
	}
}

func TestFinishDoesNotExposeSemanticErrorCause(t *testing.T) {
	err := failure.Wrap(failure.CodePINInvalid, errors.New("private semantic cause"))

	entry := Finish(model.LogEntry{}, time.Now(), err)
	if entry.ErrorMessage != "" {
		t.Fatalf("error message = %q, want empty", entry.ErrorMessage)
	}
}
