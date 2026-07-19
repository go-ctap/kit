package model

type SetPINOperation struct {
	NewPIN string `json:"newPIN"`
	DryRun bool   `json:"dryRun,omitempty"`
}

func (SetPINOperation) Kind() OperationKind { return OperationSetPIN }
func (op SetPINOperation) IsDryRun() bool   { return op.DryRun }
func (SetPINOperation) ctapkitOperation()   {}

type ChangePINOperation struct {
	CurrentPIN string `json:"currentPIN"`
	NewPIN     string `json:"newPIN"`
	DryRun     bool   `json:"dryRun,omitempty"`
}

func (ChangePINOperation) Kind() OperationKind { return OperationChangePIN }
func (op ChangePINOperation) IsDryRun() bool   { return op.DryRun }
func (ChangePINOperation) ctapkitOperation()   {}
