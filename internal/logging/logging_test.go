package logging

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

func TestPayloadUsesStableIndentedJSON(t *testing.T) {
	payload := Payload(SafeValue(struct {
		Command string         `json:"command"`
		Params  map[string]any `json:"params"`
	}{
		Command: "authenticatorGetInfo",
		Params:  map[string]any{"enabled": true},
	}))
	if payload == nil {
		t.Fatal("Payload returned nil")
	}

	want := "{\n  \"command\": \"authenticatorGetInfo\",\n  \"params\": {\n    \"enabled\": true\n  }\n}"
	if payload.JSON != want {
		t.Fatalf("payload JSON = %q, want %q", payload.JSON, want)
	}
	if payload.OriginalBytes != len(want) || payload.StoredBytes != len(want) || payload.Truncated {
		t.Fatalf("payload metadata = %#v", payload)
	}
}

func TestPayloadTruncationIsValidAndBounded(t *testing.T) {
	payload := Payload(SafeValue(map[string]string{"value": strings.Repeat("safe-payload-", 10_000)}))
	if payload == nil {
		t.Fatal("Payload returned nil")
	}
	if !payload.Truncated {
		t.Fatal("payload was not truncated")
	}
	if payload.OriginalBytes <= MaxPayloadBytes {
		t.Fatalf("original bytes = %d, want greater than %d", payload.OriginalBytes, MaxPayloadBytes)
	}
	if payload.StoredBytes > MaxPayloadBytes || payload.StoredBytes != len(payload.JSON) {
		t.Fatalf("stored bytes = %d, JSON bytes = %d", payload.StoredBytes, len(payload.JSON))
	}

	var stored struct {
		Truncated     bool   `json:"truncated"`
		OriginalBytes int    `json:"originalBytes"`
		Preview       string `json:"preview"`
	}
	if err := json.Unmarshal([]byte(payload.JSON), &stored); err != nil {
		t.Fatalf("truncated JSON is invalid: %v", err)
	}
	if !stored.Truncated || stored.OriginalBytes != payload.OriginalBytes || stored.Preview == "" {
		t.Fatalf("truncated JSON = %#v", stored)
	}
}

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
