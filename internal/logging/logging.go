package logging

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/go-ctap/ctap/diagnostic"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

const (
	MaxPayloadBytes = 64 * 1024
	previewBytes    = 4 * 1024
)

type correlationKey struct{}
type recorderKey struct{}

type correlation struct {
	selectionID   string
	operationID   string
	operationKind model.OperationKind
}

func WithCorrelation(
	ctx context.Context,
	selectionID string,
	operationID string,
	operationKind model.OperationKind,
) context.Context {
	return context.WithValue(ctx, correlationKey{}, correlation{
		selectionID:   selectionID,
		operationID:   operationID,
		operationKind: operationKind,
	})
}

func Correlation(ctx context.Context) (string, string, model.OperationKind) {
	value, _ := ctx.Value(correlationKey{}).(correlation)

	return value.selectionID, value.operationID, value.operationKind
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

func CBORDiagnosticPayload(message diagnostic.Message) *model.LogPayload {
	stored := message.Notation
	truncated := len(stored) > MaxPayloadBytes
	if truncated {
		stored = safePreview([]byte(stored), previewBytes)
	}
	if message.Bytes < 0 {
		message.Bytes = 0
	}

	return &model.LogPayload{
		CBORDiagnostic:  stored,
		DiagnosticError: safePreview([]byte(message.Error), previewBytes),
		OriginalBytes:   message.Bytes,
		StoredBytes:     len(stored),
		Truncated:       truncated,
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
	return FinishElapsed(entry, time.Since(started), err)
}

func FinishElapsed(entry model.LogEntry, duration time.Duration, err error) model.LogEntry {
	entry.ErrorMessage = TransportErrorMessage(err)
	entry.DurationMilliseconds = duration.Milliseconds()

	return finishFailure(entry, failure.Snapshot(err))
}

func TransportErrorMessage(err error) string {
	code, ok := failure.CodeOf(err)
	if !ok || code != failure.CodeTransportFailure &&
		code != failure.CodeTransportPermissionDenied &&
		code != failure.CodeTransportProxyUnavailable {
		return ""
	}

	typed, ok := errors.AsType[*failure.Error](err)
	if !ok || typed.Unwrap() == nil {
		return ""
	}

	return safePreview([]byte(typed.Unwrap().Error()), previewBytes)
}

func FinishFailure(entry model.LogEntry, started time.Time, snapshot *failure.Failure) model.LogEntry {
	entry.DurationMilliseconds = time.Since(started).Milliseconds()

	return finishFailure(entry, snapshot)
}

func finishFailure(entry model.LogEntry, snapshot *failure.Failure) model.LogEntry {
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
