package model

import "github.com/go-ctap/kit/model/config"

type ConfigStatusOperation struct{}

func (ConfigStatusOperation) Kind() OperationKind { return OperationConfigStatus }
func (ConfigStatusOperation) IsDryRun() bool      { return false }
func (ConfigStatusOperation) ctapkitOperation()   {}

type SetAlwaysUVOperation struct {
	Target config.AlwaysUVTarget `json:"target"`
	DryRun bool                  `json:"dryRun,omitempty"`
}

func (SetAlwaysUVOperation) Kind() OperationKind { return OperationSetAlwaysUV }
func (op SetAlwaysUVOperation) IsDryRun() bool   { return op.DryRun }
func (SetAlwaysUVOperation) ctapkitOperation()   {}

type SetMinPINLengthOperation struct {
	NewMinPINLength     *uint    `json:"newMinPINLength,omitempty"`
	MinPINLengthRPIDs   []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePIN      bool     `json:"forceChangePin,omitempty"`
	PINComplexityPolicy bool     `json:"pinComplexityPolicy,omitempty"`
	DryRun              bool     `json:"dryRun,omitempty"`
}

func (SetMinPINLengthOperation) Kind() OperationKind { return OperationSetMinPINLength }
func (op SetMinPINLengthOperation) IsDryRun() bool   { return op.DryRun }
func (SetMinPINLengthOperation) ctapkitOperation()   {}

type EnableLongTouchForResetOperation struct {
	DryRun bool `json:"dryRun,omitempty"`
}

func (EnableLongTouchForResetOperation) Kind() OperationKind {
	return OperationEnableLongTouchForReset
}
func (op EnableLongTouchForResetOperation) IsDryRun() bool { return op.DryRun }
func (EnableLongTouchForResetOperation) ctapkitOperation() {}
