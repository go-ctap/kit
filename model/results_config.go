package model

import "github.com/go-ctap/kit/model/config"

type ConfigStatusOutput struct {
	Report config.StatusReport `json:"report"`
}

type BioSensorOutput struct {
	Report config.BioSensorReport `json:"report"`
}

type BioListOutput struct {
	Report config.BioListReport `json:"report"`
}

type BioEnrollOutput struct {
	Preview config.BioEnrollPreview `json:"preview"`
	Result  *config.BioEnrollResult `json:"result"`
}

type BioMutationOutput struct {
	Preview config.BioMutationPreview `json:"preview"`
	Result  *config.BioMutationResult `json:"result"`
}

type ResetFactoryOutput struct {
	Preview config.ResetPreview `json:"preview"`
	Result  *config.ResetResult `json:"result"`
}

type PINOutput struct {
	Preview config.PINMutationPreview `json:"preview"`
	Result  *config.PINMutationResult `json:"result"`
}

type AuthenticatorConfigOutput struct {
	Preview config.AuthenticatorConfigPreview `json:"preview"`
	Result  *config.AuthenticatorConfigResult `json:"result"`
}
