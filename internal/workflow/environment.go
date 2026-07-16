package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/report"
)

type Environment struct {
	Selected          report.DeviceReport
	Authenticator     authenticator.Device
	Events            EventEmitter
	Interactions      InteractionRequester
	Cache             CacheStore
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
}

type CacheStore interface {
	Credential() (appcredentials.InventoryReport, bool)
	SetCredential(appcredentials.InventoryReport)
	LargeBlobList() (applargeblobs.ListReport, bool)
	SetLargeBlobList(applargeblobs.ListReport)
	Config() (appconfig.StatusReport, bool)
	SetConfig(appconfig.StatusReport)
	InvalidateAll()
	InvalidateCredentials()
	InvalidateLargeBlobs()
	InvalidateConfig()
	InvalidateToken()
	InvalidateTokenUnlessPermission(protocol.Permission)
}
