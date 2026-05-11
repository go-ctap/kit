package model

type BioSensorInfoOperation struct{}

func (BioSensorInfoOperation) Kind() OperationKind { return OperationBioSensorInfo }
func (BioSensorInfoOperation) IsDryRun() bool      { return false }
func (BioSensorInfoOperation) ctapkitOperation()   {}

type BioListOperation struct{}

func (BioListOperation) Kind() OperationKind { return OperationBioList }
func (BioListOperation) IsDryRun() bool      { return false }
func (BioListOperation) ctapkitOperation()   {}

type BioEnrollOperation struct {
	TimeoutMilliseconds uint   `json:"timeoutMilliseconds,omitempty"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (BioEnrollOperation) Kind() OperationKind { return OperationBioEnroll }
func (op BioEnrollOperation) IsDryRun() bool   { return op.DryRun }
func (BioEnrollOperation) ctapkitOperation()   {}

type BioRenameOperation struct {
	TemplateIDHex       string `json:"templateIdHex"`
	FriendlyName        string `json:"friendlyName"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (BioRenameOperation) Kind() OperationKind { return OperationBioRename }
func (op BioRenameOperation) IsDryRun() bool   { return op.DryRun }
func (BioRenameOperation) ctapkitOperation()   {}

type BioRemoveOperation struct {
	TemplateIDHex       string `json:"templateIdHex"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (BioRemoveOperation) Kind() OperationKind { return OperationBioRemove }
func (op BioRemoveOperation) IsDryRun() bool   { return op.DryRun }
func (BioRemoveOperation) ctapkitOperation()   {}
