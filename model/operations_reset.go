package model

type ResetFactoryOperation struct {
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (ResetFactoryOperation) Kind() OperationKind { return OperationResetFactory }
func (op ResetFactoryOperation) IsDryRun() bool   { return op.DryRun }
func (ResetFactoryOperation) ctapkitOperation()   {}
