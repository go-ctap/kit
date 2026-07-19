package config

type BioEnrollOutput struct {
	Preview BioEnrollPreview `json:"preview"`
	Result  *BioEnrollResult `json:"result"`
}

type BioMutationOutput struct {
	Preview BioMutationPreview `json:"preview"`
	Result  *BioMutationResult `json:"result"`
}

type ResetFactoryOutput struct {
	Preview ResetPreview `json:"preview"`
	Result  *ResetResult `json:"result"`
}

type PINOutput struct {
	Preview PINMutationPreview `json:"preview"`
	Result  *PINMutationResult `json:"result"`
}

type AuthenticatorConfigOutput struct {
	Preview AuthenticatorConfigPreview `json:"preview"`
	Result  *AuthenticatorConfigResult `json:"result"`
}
