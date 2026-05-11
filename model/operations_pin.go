package model

import "encoding/json"

type SetPINOperation struct {
	// NewPIN is accepted by UnmarshalJSON as "newPIN" but intentionally omitted
	// during marshal so callers cannot accidentally log or expose PINs.
	NewPIN              string `json:"-"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (SetPINOperation) Kind() OperationKind { return OperationSetPIN }
func (op SetPINOperation) IsDryRun() bool   { return op.DryRun }
func (SetPINOperation) ctapkitOperation()   {}

func (op *SetPINOperation) UnmarshalJSON(data []byte) error {
	type pinPayload struct {
		NewPIN              string `json:"newPIN"`
		Confirmed           bool   `json:"confirmed,omitempty"`
		ConfirmationMessage string `json:"confirmationMessage,omitempty"`
		DryRun              bool   `json:"dryRun,omitempty"`
	}

	var payload pinPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	op.NewPIN = payload.NewPIN
	op.Confirmed = payload.Confirmed
	op.ConfirmationMessage = payload.ConfirmationMessage
	op.DryRun = payload.DryRun

	return nil
}

type ChangePINOperation struct {
	// CurrentPIN and NewPIN are accepted by UnmarshalJSON as "currentPIN" and
	// "newPIN" but intentionally omitted during marshal so callers cannot
	// accidentally log or expose PINs.
	CurrentPIN          string `json:"-"`
	NewPIN              string `json:"-"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

func (ChangePINOperation) Kind() OperationKind { return OperationChangePIN }
func (op ChangePINOperation) IsDryRun() bool   { return op.DryRun }
func (ChangePINOperation) ctapkitOperation()   {}

func (op *ChangePINOperation) UnmarshalJSON(data []byte) error {
	type pinPayload struct {
		CurrentPIN          string `json:"currentPIN"`
		NewPIN              string `json:"newPIN"`
		Confirmed           bool   `json:"confirmed,omitempty"`
		ConfirmationMessage string `json:"confirmationMessage,omitempty"`
		DryRun              bool   `json:"dryRun,omitempty"`
	}

	var payload pinPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	op.CurrentPIN = payload.CurrentPIN
	op.NewPIN = payload.NewPIN
	op.Confirmed = payload.Confirmed
	op.ConfirmationMessage = payload.ConfirmationMessage
	op.DryRun = payload.DryRun

	return nil
}
