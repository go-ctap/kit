package model

import "github.com/go-ctap/kit/model/config"

type ConfigStatusOperation struct{}

func (ConfigStatusOperation) Kind() OperationKind { return OperationConfigStatus }
func (ConfigStatusOperation) IsDryRun() bool      { return false }
func (ConfigStatusOperation) ctapkitOperation()   {}

type SetAlwaysUVOperation struct {
	Target              config.AlwaysUVTarget `json:"target"`
	Confirmed           bool                  `json:"confirmed,omitempty"`
	ConfirmationMessage string                `json:"confirmationMessage,omitempty"`
	DryRun              bool                  `json:"dryRun,omitempty"`
}

func (SetAlwaysUVOperation) Kind() OperationKind { return OperationSetAlwaysUV }
func (op SetAlwaysUVOperation) IsDryRun() bool   { return op.DryRun }
func (SetAlwaysUVOperation) ctapkitOperation()   {}

type SetMinPINLengthOperation struct {
	Length              uint     `json:"newMinPINLength"`
	RPIDs               []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePin      bool     `json:"forceChangePin,omitempty"`
	PinComplexityPolicy bool     `json:"pinComplexityPolicy,omitempty"`
	Confirmed           bool     `json:"confirmed,omitempty"`
	ConfirmationMessage string   `json:"confirmationMessage,omitempty"`
	DryRun              bool     `json:"dryRun,omitempty"`
}

func (SetMinPINLengthOperation) Kind() OperationKind { return OperationSetMinPINLength }
func (op SetMinPINLengthOperation) IsDryRun() bool   { return op.DryRun }
func (SetMinPINLengthOperation) ctapkitOperation()   {}
