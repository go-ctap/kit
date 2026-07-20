package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
)

type Environment struct {
	Selected     report.DeviceReport
	Events       EventEmitter
	Interactions InteractionRequester
	Tokens       TokenService
	Effects      *rtruntime.StateEffects
}

type EventEmitter interface {
	Emit(context.Context, model.OperationEvent)
}

type InteractionRequester interface {
	RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
}

type TokenService interface {
	Use(
		context.Context,
		rtruntime.TokenUse,
		func([]byte) error,
	) error
	Invalidate()
	InvalidateUnlessPermission(protocol.Permission)
}
