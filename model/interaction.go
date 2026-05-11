package model

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
	Kind        InteractionKind `json:"kind"`
	Message     string          `json:"message,omitempty"`
	Permission  string          `json:"permission,omitempty"`
	Destructive bool            `json:"destructive,omitempty"`
	Preview     any             `json:"preview,omitempty"`
}

type InteractionResponse struct {
	PIN       []byte `json:"-"`
	Confirmed bool   `json:"confirmed,omitempty"`
	Canceled  bool   `json:"canceled,omitempty"`
}
