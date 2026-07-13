package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/transport"
)

type authenticatorOpenFunc func(ctx context.Context, mode transport.Mode, path string) (authenticator.Device, error)

func openAuthenticator(ctx context.Context, mode transport.Mode, path string) (authenticator.Device, error) {
	return authenticator.Open(ctx, mode, path)
}
