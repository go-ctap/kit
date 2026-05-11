// Package service provides an application-facing orchestration layer on top of
// the public ctapkit runtime facade.
package service

import (
	"encoding/json"

	"github.com/go-ctap/kit/model"
	appmds "github.com/go-ctap/kit/model/mds"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

type SessionID string

type OperationID string

type InteractionID string

const (
	EventDiscoveryCompleted   = "ctapkit:discovery-completed"
	EventSessionOpened        = "ctapkit:session-opened"
	EventSessionClosed        = "ctapkit:session-closed"
	EventOperationEvent       = "ctapkit:operation-event"
	EventInteractionRequested = "ctapkit:interaction-requested"
	EventOperationCompleted   = "ctapkit:operation-completed"
)

type DiscoverRequest struct {
	Mode transport.Mode `json:"mode,omitempty"`
}

type DiscoverySnapshot struct {
	Devices []report.DeviceReport `json:"devices"`
}

type OpenSessionRequest struct {
	Selector string `json:"selector,omitempty"`
}

type SessionSnapshot struct {
	ID      SessionID         `json:"id"`
	Info    model.SessionInfo `json:"info"`
	Running bool              `json:"running,omitempty"`
}

type RunOperationRequest struct {
	SessionID        SessionID              `json:"sessionId"`
	Operation        model.Operation        `json:"-"`
	VerificationFlow model.VerificationFlow `json:"verificationFlow,omitempty"`
}

type OperationEnvelope struct {
	OperationID OperationID           `json:"operationId"`
	SessionID   SessionID             `json:"sessionId"`
	Kind        model.OperationKind   `json:"kind"`
	Result      model.OperationResult `json:"result,omitempty"`
	Error       *RuntimeErrorEnvelope `json:"error,omitempty"`
}

type CancelOperationRequest struct {
	OperationID OperationID `json:"operationId"`
}

type InteractionPrompt struct {
	InteractionID InteractionID            `json:"interactionId"`
	OperationID   OperationID              `json:"operationId"`
	SessionID     SessionID                `json:"sessionId"`
	Request       model.InteractionRequest `json:"request"`
}

type InteractionAnswer struct {
	InteractionID InteractionID `json:"interactionId"`
	PIN           string        `json:"pin,omitempty"`
	Confirmed     bool          `json:"confirmed,omitempty"`
	Canceled      bool          `json:"canceled,omitempty"`
}

func (a InteractionAnswer) MarshalJSON() ([]byte, error) {
	type publicInteractionAnswer struct {
		InteractionID InteractionID `json:"interactionId"`
		Confirmed     bool          `json:"confirmed,omitempty"`
		Canceled      bool          `json:"canceled,omitempty"`
	}

	return json.Marshal(publicInteractionAnswer{
		InteractionID: a.InteractionID,
		Confirmed:     a.Confirmed,
		Canceled:      a.Canceled,
	})
}

type OperationEventEnvelope struct {
	OperationID OperationID          `json:"operationId,omitempty"`
	SessionID   SessionID            `json:"sessionId"`
	Event       model.OperationEvent `json:"event"`
}

type MDSLookupRequest struct {
	AAGUID   string `json:"aaguid"`
	Source   string `json:"source,omitempty"`
	CacheDir string `json:"cacheDir,omitempty"`
	Refresh  bool   `json:"refresh,omitempty"`
}

type MDSLookupEnvelope struct {
	Result appmds.LookupResult `json:"result"`
}

type RuntimeErrorEnvelope struct {
	Category model.ErrorCategory `json:"category,omitempty"`
	Message  string              `json:"message"`
}
