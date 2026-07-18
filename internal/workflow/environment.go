package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
)

type Environment struct {
	Selected          report.DeviceReport
	Authenticator     authenticator.Device
	Events            EventEmitter
	Interactions      InteractionRequester
	Tokens            TokenService
	StrictPermissions bool
}

type EventEmitter interface {
	Emit(model.OperationEvent)
}

type InteractionRequester interface {
	RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
}

type TokenService interface {
	Acquire(context.Context, authenticator.TokenProvider, protocol.Permission, string) ([]byte, error)
	Use(
		context.Context,
		authenticator.TokenProvider,
		protocol.Permission,
		string,
		func([]byte) error,
	) error
	Invalidate()
	InvalidateUnlessPermission(protocol.Permission)
}
