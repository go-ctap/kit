package service

import (
	"slices"
	"strconv"
	"time"

	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
)

func (s *Service) ReadLogs(req ReadLogsRequest) model.LogJournalBatch {
	return s.logs.Read(req.After)
}

func (s *Service) ClearLogs() LogCursor {
	return LogCursor{Sequence: s.logs.Clear()}
}

func (s *Service) CurrentLogCursor() LogCursor {
	return LogCursor{Sequence: s.logs.Cursor()}
}

func (s *Service) LogChanges() <-chan struct{} {
	return s.logs.Changes()
}

func operationRequestLogValue(req OperationRequest, operation model.Operation) kitlog.SafeJSONValue {
	value := kitlog.SafeValue(operation)

	return kitlog.SafeJSONValue{
		Value: map[string]any{
			"sessionId":        req.SessionID,
			"verificationFlow": req.VerificationFlow,
			"kind":             operation.Kind(),
			"input":            value.Value,
		},
		RedactedFields: prefixLogFields(value.RedactedFields, "request.input"),
	}
}

func operationEnvelopeLogValue(envelope operationEnvelope) kitlog.SafeJSONValue {
	var result any
	var redacted []string
	if envelope.Result != nil {
		value := kitlog.SafeValue(envelope.Result)
		result = value.Value
		redacted = prefixLogFields(value.RedactedFields, "response.result")
	}

	return kitlog.SafeJSONValue{
		Value: map[string]any{
			"operationId": envelope.OperationID,
			"sessionId":   envelope.SessionID,
			"kind":        envelope.Kind,
			"result":      result,
			"error":       envelope.Error,
		},
		RedactedFields: redacted,
	}
}

func interactionRequestLogValue(request model.InteractionRequest) kitlog.SafeJSONValue {
	redacted := make([]string, 0, 2)
	if request.Message != "" {
		request.Message = kitlog.Redacted
		redacted = append(redacted, "request.message")
	}
	value := kitlog.SafeValue(request)
	redacted = slices.Concat(redacted, prefixLogFields(value.RedactedFields, "request"))

	return kitlog.SafeJSONValue{Value: value.Value, RedactedFields: redacted}
}

func operationEventLogEntry(state *operationState, event model.OperationEvent) model.LogEntry {
	params := map[string]string{"stage": string(event.Stage)}
	if event.Kind != "" {
		params["interactionKind"] = string(event.Kind)
	}
	if event.Completed != nil {
		params["completed"] = strconv.FormatUint(*event.Completed, 10)
	}
	if event.Total != nil {
		params["total"] = strconv.FormatUint(*event.Total, 10)
	}
	if event.SampleStatus != "" {
		params["sampleStatus"] = event.SampleStatus
	}

	return model.LogEntry{
		Timestamp:     time.Now().UTC(),
		Layer:         model.LogLayerOperation,
		Level:         model.LogLevelDebug,
		Outcome:       model.LogOutcomeEvent,
		Code:          model.LogCodeOperationProgress,
		Params:        params,
		OperationKind: state.kind,
		SessionID:     string(state.sessionID),
		OperationID:   string(state.id),
	}
}

func prefixLogFields(fields []string, prefix string) []string {
	prefixed := make([]string, 0, len(fields))
	for _, field := range fields {
		prefixed = append(prefixed, prefix+"."+field)
	}

	return prefixed
}
