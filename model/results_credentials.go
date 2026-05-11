package model

import "github.com/go-ctap/kit/model/credentials"

type CredentialsOutput struct {
	Report credentials.InventoryReport `json:"report"`
}

func (CredentialsOutput) ctapkitResult() {}

type CredentialDeleteOutput struct {
	Preview credentials.DeletePreview `json:"preview"`
	Result  *credentials.DeleteResult `json:"result"`
}

func (CredentialDeleteOutput) ctapkitResult() {}

type CredentialUpdateOutput struct {
	Preview credentials.UpdateUserPreview `json:"preview"`
	Result  *credentials.UpdateUserResult `json:"result"`
}

func (CredentialUpdateOutput) ctapkitResult() {}
