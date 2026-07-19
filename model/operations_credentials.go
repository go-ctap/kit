package model

import "github.com/go-ctap/kit/model/credentials"

type ListCredentialsOperation struct{}

type CredentialStoreStateOperation struct{}

func (CredentialStoreStateOperation) Kind() OperationKind { return OperationCredentialStoreState }
func (CredentialStoreStateOperation) IsDryRun() bool      { return false }
func (CredentialStoreStateOperation) ctapkitOperation()   {}

func (ListCredentialsOperation) Kind() OperationKind { return OperationListCredentials }
func (ListCredentialsOperation) IsDryRun() bool      { return false }
func (ListCredentialsOperation) ctapkitOperation()   {}

type DeleteCredentialOperation struct {
	CredentialIDHex string `json:"credentialIdHex"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

func (DeleteCredentialOperation) Kind() OperationKind { return OperationDeleteCredential }
func (op DeleteCredentialOperation) IsDryRun() bool   { return op.DryRun }
func (DeleteCredentialOperation) ctapkitOperation()   {}

type UpdateCredentialUserOperation struct {
	Target          credentials.CredentialTarget `json:"target"`
	UserIDHex       string                       `json:"userIdHex,omitempty"`
	Name            string                       `json:"name,omitempty"`
	DisplayName     string                       `json:"displayName,omitempty"`
	UserIDProvided  bool                         `json:"userIdProvided,omitempty"`
	NameProvided    bool                         `json:"nameProvided,omitempty"`
	DisplayProvided bool                         `json:"displayProvided,omitempty"`
	DryRun          bool                         `json:"dryRun,omitempty"`
}

func (UpdateCredentialUserOperation) Kind() OperationKind { return OperationUpdateCredentialUser }
func (op UpdateCredentialUserOperation) IsDryRun() bool   { return op.DryRun }
func (UpdateCredentialUserOperation) ctapkitOperation()   {}
