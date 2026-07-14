//go:build linux || darwin

package transport

import (
	"context"

	"github.com/go-ctap/ctap/discover"
)

func NewDefaultResolver() ProviderResolver {
	return linuxResolver{provider: hidProvider{}}
}

type linuxResolver struct {
	provider Provider
}

func (r linuxResolver) Resolve(_ context.Context, requested Mode) (ResolvedProvider, error) {
	switch requested {
	case ModeAuto, ModeHID:
		return ResolvedProvider{Mode: ModeHID, Provider: r.provider}, nil
	default:
		return ResolvedProvider{}, unsupportedModeError()
	}
}

type hidProvider struct{}

func (hidProvider) Check(context.Context) error {
	return nil
}

func (hidProvider) List(ctx context.Context) ([]Descriptor, error) {
	infos, err := discover.EnumerateFIDODevices(ctx)
	if err != nil {
		return nil, transportError(err)
	}

	return descriptorsFromDeviceInfos(ModeHID, infos), nil
}
