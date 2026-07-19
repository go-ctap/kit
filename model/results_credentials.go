package model

import "github.com/go-ctap/kit/model/credentials"

type CredentialStoreStateOutput struct {
	Result credentials.StoreStateResult `json:"result"`
}

type CredentialsOutput struct {
	Report credentials.InventoryReport `json:"report"`
}

type CredentialDeleteOutput struct {
	Preview credentials.DeletePreview `json:"preview"`
	Result  *credentials.DeleteResult `json:"result"`
}

type CredentialUpdateOutput struct {
	Preview credentials.UpdateUserPreview `json:"preview"`
	Result  *credentials.UpdateUserResult `json:"result"`
}
