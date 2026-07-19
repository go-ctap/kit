package model

import (
	"context"

	"github.com/go-ctap/kit/model/failure"
)

type InteractionHandler interface {
	RequestInteraction(context.Context, InteractionRequest) (InteractionResponse, error)
}

type InteractionKind string

const (
	InteractionKindPIN              InteractionKind = "pin"
	InteractionKindUserVerification InteractionKind = "user-verification"
	InteractionKindTouch            InteractionKind = "touch"
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
	PIN      []byte `json:"-"`
	Canceled bool   `json:"canceled,omitempty"`
}
