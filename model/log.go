package model

import (
	"time"

	"github.com/go-ctap/kit/model/failure"
)

type LogLevel string

const (
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarning LogLevel = "warning"
	LogLevelError   LogLevel = "error"
)

type LogLayer string

const (
	LogLayerService     LogLayer = "service"
	LogLayerSelection   LogLayer = "selection"
	LogLayerOperation   LogLayer = "operation"
	LogLayerInteraction LogLayer = "interaction"
	LogLayerCTAP        LogLayer = "ctap"
)

type LogOutcome string

const (
	LogOutcomeEvent     LogOutcome = "event"
	LogOutcomeSucceeded LogOutcome = "succeeded"
	LogOutcomeFailed    LogOutcome = "failed"
	LogOutcomeCanceled  LogOutcome = "canceled"
)

type LogCode string

const (
	LogCodeDiscoveryRun       LogCode = "discovery.run"
	LogCodeDiscoveryChanged   LogCode = "discovery.changed"
	LogCodeMDSLookup          LogCode = "mds.lookup"
	LogCodeSelectionOpen      LogCode = "selection.open"
	LogCodeSelectionClose     LogCode = "selection.close"
	LogCodeOperationRun       LogCode = "operation.run"
	LogCodeOperationProgress  LogCode = "operation.progress"
	LogCodeInteractionRequest LogCode = "interaction.request"
	LogCodeInteractionResolve LogCode = "interaction.resolve"
	LogCodeCTAPCommand        LogCode = "ctap.command"
)

type LogPayload struct {
	JSON            string `json:"json,omitempty"`
	CBORDiagnostic  string `json:"cborDiagnostic,omitempty"`
	DiagnosticError string `json:"diagnosticError,omitempty"`
	OriginalBytes   int    `json:"originalBytes"`
	StoredBytes     int    `json:"storedBytes"`
	Truncated       bool   `json:"truncated"`
}

type LogEntry struct {
	Timestamp            time.Time         `json:"timestamp"`
	DurationMilliseconds int64             `json:"durationMilliseconds,omitempty"`
	Layer                LogLayer          `json:"layer"`
	Level                LogLevel          `json:"level"`
	Outcome              LogOutcome        `json:"outcome"`
	Code                 LogCode           `json:"code"`
	Params               map[string]string `json:"params,omitempty"`
	DryRun               bool              `json:"dryRun,omitempty"`
	OperationKind        OperationKind     `json:"operationKind,omitempty"`
	Command              string            `json:"command,omitempty"`
	CommandCode          uint8             `json:"commandCode,omitempty"`
	SubCommand           string            `json:"subCommand,omitempty"`
	SubCommandCode       *uint64           `json:"subCommandCode,omitempty"`
	Request              *LogPayload       `json:"request,omitempty"`
	Response             *LogPayload       `json:"response,omitempty"`
	Error                *failure.Failure  `json:"error,omitempty"`
	ErrorMessage         string            `json:"errorMessage,omitempty"`
	RedactedFields       []string          `json:"redactedFields,omitempty"`
	SelectionID          string            `json:"selectionId,omitempty"`
	OperationID          string            `json:"operationId,omitempty"`
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
