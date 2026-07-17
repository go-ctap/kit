package model

import "github.com/go-ctap/kit/model/webauthn"

type MakeCredentialOperation struct {
	webauthn.MakeCredentialInput
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (MakeCredentialOperation) Kind() OperationKind { return OperationMakeCredential }
func (op MakeCredentialOperation) IsDryRun() bool   { return op.DryRun }
func (MakeCredentialOperation) ctapkitOperation()   {}

type GetAssertionOperation struct {
	webauthn.GetAssertionInput
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (GetAssertionOperation) Kind() OperationKind { return OperationGetAssertion }
func (op GetAssertionOperation) IsDryRun() bool   { return op.DryRun }
func (GetAssertionOperation) ctapkitOperation()   {}
