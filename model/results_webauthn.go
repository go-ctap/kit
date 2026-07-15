package model

import "github.com/go-ctap/kit/model/webauthn"

type MakeCredentialOutput struct {
	Preview webauthn.MakeCredentialPreview `json:"preview"`
	Result  *webauthn.MakeCredentialResult `json:"result"`
}

func (MakeCredentialOutput) ctapkitResult() {}

type GetAssertionOutput struct {
	Preview webauthn.GetAssertionPreview `json:"preview"`
	Result  *webauthn.GetAssertionResult `json:"result"`
}

func (GetAssertionOutput) ctapkitResult() {}
