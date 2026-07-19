package model

import "github.com/go-ctap/kit/model/credentials"

type DeleteCredentialOperation struct {
	CredentialIDHex string `json:"credentialIdHex"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

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
