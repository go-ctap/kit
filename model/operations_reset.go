package model

type ResetFactoryOperation struct {
	DryRun bool `json:"dryRun,omitempty"`
}

func (ResetFactoryOperation) Kind() OperationKind { return OperationResetFactory }
func (op ResetFactoryOperation) IsDryRun() bool   { return op.DryRun }
func (ResetFactoryOperation) ctapkitOperation()   {}
