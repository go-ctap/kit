package model

import (
	"time"

	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/operation"
)

type LogOutcome string

const (
	LogOutcomeSucceeded LogOutcome = "succeeded"
	LogOutcomeFailed    LogOutcome = "failed"
	LogOutcomeCanceled  LogOutcome = "canceled"
)

type LogPayload struct {
	CBORDiagnostic  string `json:"cborDiagnostic,omitempty"`
	DiagnosticError string `json:"diagnosticError,omitempty"`
	OriginalBytes   int    `json:"originalBytes"`
	StoredBytes     int    `json:"storedBytes"`
	Truncated       bool   `json:"truncated"`
}

type LogEntry struct {
	Timestamp            time.Time        `json:"timestamp"`
	DurationMilliseconds int64            `json:"durationMilliseconds,omitempty"`
	Outcome              LogOutcome       `json:"outcome"`
	OperationKind        operation.Kind   `json:"operationKind,omitempty"`
	Command              string           `json:"command,omitempty"`
	CommandCode          uint8            `json:"commandCode,omitempty"`
	SubCommand           string           `json:"subCommand,omitempty"`
	SubCommandCode       *uint64          `json:"subCommandCode,omitempty"`
	Request              *LogPayload      `json:"request,omitempty"`
	Response             *LogPayload      `json:"response,omitempty"`
	Error                *failure.Failure `json:"error,omitempty"`
	ErrorMessage         string           `json:"errorMessage,omitempty"`
	RedactedFields       []string         `json:"redactedFields,omitempty"`
}

type LogJournalRecord struct {
	Sequence uint64   `json:"sequence"`
	Entry    LogEntry `json:"entry"`
}

type LogJournalBatch struct {
	Entries   []LogJournalRecord `json:"entries"`
	Cursor    uint64             `json:"cursor"`
	Truncated bool               `json:"truncated,omitempty"`
}
