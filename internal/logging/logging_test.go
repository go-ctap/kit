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

func TestFinishElapsedAddsBoundedTransportErrorMessage(t *testing.T) {
	err := failure.Wrap(
		failure.CodeTransportFailure,
		&ctaptransport.IOError{Operation: ctaptransport.IORead, Err: io.ErrClosedPipe},
	)

	entry := FinishElapsed(model.LogEntry{}, time.Second, err)
	if entry.ErrorMessage != "transport read: io: read/write on closed pipe" {
		t.Fatalf("error message = %q", entry.ErrorMessage)
	}

	longErr := failure.Wrap(failure.CodeTransportFailure, errors.New(strings.Repeat("x", previewBytes+100)))
	entry = FinishElapsed(model.LogEntry{}, time.Second, longErr)
	if len(entry.ErrorMessage) != previewBytes {
		t.Fatalf("error message bytes = %d, want %d", len(entry.ErrorMessage), previewBytes)
	}
}

func TestFinishElapsedDoesNotExposeSemanticErrorCause(t *testing.T) {
	err := failure.Wrap(failure.CodePINInvalid, errors.New("private semantic cause"))

	entry := FinishElapsed(model.LogEntry{}, time.Second, err)
	if entry.ErrorMessage != "" {
		t.Fatalf("error message = %q, want empty", entry.ErrorMessage)
	}
}
