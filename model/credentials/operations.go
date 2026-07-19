package credentials

type DeleteOperation struct {
	CredentialIDHex string `json:"credentialIDHex"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type UpdateUserOperation struct {
	Target          CredentialTarget `json:"target"`
	UserIDHex       string           `json:"userIDHex,omitempty"`
	Name            string           `json:"name,omitempty"`
	DisplayName     string           `json:"displayName,omitempty"`
	UserIDProvided  bool             `json:"userIDProvided,omitempty"`
	NameProvided    bool             `json:"nameProvided,omitempty"`
	DisplayProvided bool             `json:"displayProvided,omitempty"`
	DryRun          bool             `json:"dryRun,omitempty"`
}
