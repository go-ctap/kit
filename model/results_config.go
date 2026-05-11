package model

import "github.com/go-ctap/kit/model/config"

type ConfigStatusOutput struct {
	Report config.StatusReport `json:"report"`
}

func (ConfigStatusOutput) ctapkitResult() {}

type BioSensorOutput struct {
	Report config.BioSensorReport `json:"report"`
}

func (BioSensorOutput) ctapkitResult() {}

type BioListOutput struct {
	Report config.BioListReport `json:"report"`
}

func (BioListOutput) ctapkitResult() {}

type BioEnrollOutput struct {
	Preview config.BioEnrollPreview `json:"preview"`
	Result  *config.BioEnrollResult `json:"result"`
}

func (BioEnrollOutput) ctapkitResult() {}

type BioMutationOutput struct {
	Preview config.BioMutationPreview `json:"preview"`
	Result  *config.BioMutationResult `json:"result"`
}

func (BioMutationOutput) ctapkitResult() {}

type ResetFactoryOutput struct {
	Preview config.ResetPreview `json:"preview"`
	Result  *config.ResetResult `json:"result"`
}

func (ResetFactoryOutput) ctapkitResult() {}

type PINOutput struct {
	Preview config.PINMutationPreview `json:"preview"`
	Result  *config.PINMutationResult `json:"result"`
}

func (PINOutput) ctapkitResult() {}

type AuthenticatorConfigOutput struct {
	Preview config.AuthenticatorConfigPreview `json:"preview"`
	Result  *config.AuthenticatorConfigResult `json:"result"`
}

func (AuthenticatorConfigOutput) ctapkitResult() {}
