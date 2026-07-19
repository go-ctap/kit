package model

import "context"

type OperationStage string

const (
	OperationStageInteractionRequired    OperationStage = "interaction-required"
	OperationStageEnumeratingRPs         OperationStage = "enumerating-rps"
	OperationStageEnumeratingCredentials OperationStage = "enumerating-credentials"
	OperationStageCapturingBioSample     OperationStage = "capturing-bio-sample"
)

type OperationEvent struct {
	Stage        OperationStage  `json:"stage"`
	Kind         InteractionKind `json:"kind,omitempty"`
	Message      string          `json:"message,omitempty"`
	Completed    *uint64         `json:"completed,omitempty"`
	Total        *uint64         `json:"total,omitempty"`
	SampleStatus string          `json:"sampleStatus,omitempty"`
}

type EventSink interface {
	Emit(context.Context, OperationEvent)
}

type NoopEventSink struct{}

func (NoopEventSink) Emit(context.Context, OperationEvent) {}
