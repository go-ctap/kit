package model

type ListCredentialsOperation struct {
	Refresh bool `json:"refresh,omitempty"`
}

func (ListCredentialsOperation) Kind() OperationKind { return OperationListCredentials }
func (ListCredentialsOperation) IsDryRun() bool      { return false }
func (ListCredentialsOperation) ctapkitOperation()   {}

type DeleteCredentialOperation struct {
	CredentialIDHex     string `json:"credentialIdHex"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (DeleteCredentialOperation) Kind() OperationKind { return OperationDeleteCredential }
func (op DeleteCredentialOperation) IsDryRun() bool   { return op.DryRun }
func (DeleteCredentialOperation) ctapkitOperation()   {}

type UpdateCredentialUserOperation struct {
	CredentialIDHex     string `json:"credentialIdHex"`
	UserIDHex           string `json:"userIdHex,omitempty"`
	Name                string `json:"name,omitempty"`
	DisplayName         string `json:"displayName,omitempty"`
	UserIDProvided      bool   `json:"userIdProvided,omitempty"`
	NameProvided        bool   `json:"nameProvided,omitempty"`
	DisplayProvided     bool   `json:"displayProvided,omitempty"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (UpdateCredentialUserOperation) Kind() OperationKind { return OperationUpdateCredentialUser }
func (op UpdateCredentialUserOperation) IsDryRun() bool   { return op.DryRun }
func (UpdateCredentialUserOperation) ctapkitOperation()   {}
