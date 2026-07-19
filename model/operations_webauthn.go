package model

import "github.com/go-ctap/kit/model/webauthn"

type MakeCredentialOperation struct {
	webauthn.MakeCredentialInput
	DryRun bool `json:"dryRun,omitempty"`
}

type GetAssertionOperation struct {
	webauthn.GetAssertionInput
	DryRun bool `json:"dryRun,omitempty"`
}
