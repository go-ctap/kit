package model

import "github.com/go-ctap/kit/model/failure"

type InteractionHandler interface {
	RequestInteraction(InteractionRequest) (InteractionResponse, error)
}

type InteractionKind string

const (
	InteractionKindPIN              InteractionKind = "pin"
	InteractionKindUserVerification InteractionKind = "user-verification"
	InteractionKindTouch            InteractionKind = "touch"
	InteractionKindConfirm          InteractionKind = "confirm"
)

type InteractionRequest struct {
	Kind        InteractionKind      `json:"kind"`
	Message     string               `json:"message,omitempty"`
	Permission  string               `json:"permission,omitempty"`
	Destructive bool                 `json:"destructive,omitempty"`
	Preview     any                  `json:"preview,omitempty"`
	PINState    *PINInteractionState `json:"pinState,omitempty"`
}

type PINInteractionState struct {
	Failure          *failure.Failure `json:"failure,omitempty"`
	RetriesRemaining *uint            `json:"retriesRemaining,omitempty"`
	PowerCycleState  *bool            `json:"powerCycleState,omitempty"`
}

type InteractionResponse struct {
	PIN       []byte `json:"-"`
	Confirmed bool   `json:"confirmed,omitempty"`
	Canceled  bool   `json:"canceled,omitempty"`
}
