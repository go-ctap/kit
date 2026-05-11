//go:build linux

package transport

import (
	"context"
	"fmt"

	"github.com/go-ctap/ctaphid/pkg/options"
	"github.com/go-ctap/ctaphid/pkg/sugar"
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
		return ResolvedProvider{}, fmt.Errorf("%w: %s", ErrUnsupportedMode, requested)
	}
}

type hidProvider struct{}

func (hidProvider) Check(context.Context) error {
	return nil
}

func (hidProvider) List(ctx context.Context) ([]Descriptor, error) {
	infos, err := sugar.EnumerateFIDODevices(options.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return descriptorsFromDeviceInfos(ModeHID, infos), nil
}
