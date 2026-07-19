package webauthn

type MakeCredentialOutput struct {
	Preview MakeCredentialPreview `json:"preview"`
	Result  *MakeCredentialResult `json:"result"`
}

type GetAssertionOutput struct {
	Preview GetAssertionPreview `json:"preview"`
	Result  *GetAssertionResult `json:"result"`
}
