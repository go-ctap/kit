package logging

import (
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

const (
	MaxPayloadBytes = 64 * 1024
	previewBytes    = 4 * 1024
	Redacted        = "[REDACTED]"
)

type correlationKey struct{}
type recorderKey struct{}

type correlation struct {
	sessionID     string
	operationID   string
	operationKind model.OperationKind
}

func WithCorrelation(
	ctx context.Context,
	sessionID string,
	operationID string,
	operationKind model.OperationKind,
) context.Context {
	return context.WithValue(ctx, correlationKey{}, correlation{
		sessionID:     sessionID,
		operationID:   operationID,
		operationKind: operationKind,
	})
}

func Correlation(ctx context.Context) (string, string, model.OperationKind) {
	value, _ := ctx.Value(correlationKey{}).(correlation)

	return value.sessionID, value.operationID, value.operationKind
}

type Recorder interface {
	Append(model.LogEntry)
}

func WithRecorder(ctx context.Context, recorder Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, recorder)
}

func RecorderFrom(ctx context.Context) Recorder {
	recorder, _ := ctx.Value(recorderKey{}).(Recorder)

	return recorder
}

func Payload(value SafeJSONValue) *model.LogPayload {
	raw, err := json.MarshalIndent(value.Value, "", "  ")
	if err != nil {
		return nil
	}

	originalBytes := len(raw)
	stored := raw
	truncated := false
	if originalBytes > MaxPayloadBytes {
		truncated = true
		preview := safePreview(raw, previewBytes)
		stored, err = json.MarshalIndent(struct {
			Truncated     bool   `json:"truncated"`
			OriginalBytes int    `json:"originalBytes"`
			Preview       string `json:"preview"`
		}{
			Truncated:     true,
			OriginalBytes: originalBytes,
			Preview:       preview,
		}, "", "  ")
		if err != nil || len(stored) > MaxPayloadBytes {
			return nil
		}
	}

	return &model.LogPayload{
		JSON:          string(stored),
		OriginalBytes: originalBytes,
		StoredBytes:   len(stored),
		Truncated:     truncated,
	}
}

func safePreview(raw []byte, limit int) string {
	if len(raw) <= limit {
		return string(raw)
	}

	preview := raw[:limit]
	for len(preview) > 0 && !utf8.Valid(preview) {
		preview = preview[:len(preview)-1]
	}

	return string(preview)
}

func Finish(entry model.LogEntry, started time.Time, err error) model.LogEntry {
	return FinishFailure(entry, started, failure.Snapshot(err))
}

func FinishFailure(entry model.LogEntry, started time.Time, snapshot *failure.Failure) model.LogEntry {
	entry.DurationMilliseconds = time.Since(started).Milliseconds()
	entry.Error = snapshot
	if entry.Error == nil {
		entry.Outcome = model.LogOutcomeSucceeded
		entry.Level = model.LogLevelInfo

		return entry
	}
	if entry.Error.Category == failure.CategoryCanceled {
		entry.Outcome = model.LogOutcomeCanceled
		entry.Level = model.LogLevelWarning

		return entry
	}

	entry.Outcome = model.LogOutcomeFailed
	entry.Level = model.LogLevelError

	return entry
}
