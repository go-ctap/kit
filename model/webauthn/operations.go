package webauthn

type MakeCredentialOperation struct {
	MakeCredentialInput
	DryRun bool `json:"dryRun,omitempty"`
}

type GetAssertionOperation struct {
	GetAssertionInput
	DryRun bool `json:"dryRun,omitempty"`
}
