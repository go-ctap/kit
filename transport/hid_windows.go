//go:build windows

package transport

import (
	"context"

	"github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/options"
	"golang.org/x/sys/windows"
)

func NewDefaultResolver() ProviderResolver {
	return windowsPolicy{
		isElevated: windows.GetCurrentProcessToken().IsElevated,
		hid:        hidProvider{},
		proxy:      proxyProvider{},
	}
}

type windowsPolicy struct {
	isElevated func() bool
	hid        Provider
	proxy      Provider
}

func (p windowsPolicy) Resolve(ctx context.Context, requested Mode) (ResolvedProvider, error) {
	switch requested {
	case ModeAuto:
		if p.isElevated() {
			return ResolvedProvider{Mode: ModeHID, Provider: p.hid}, nil
		}

		if err := p.proxy.Check(ctx); err != nil {
			return ResolvedProvider{}, proxyUnavailableError(err)
		}

		return ResolvedProvider{Mode: ModeWindowsProxy, Provider: p.proxy}, nil
	case ModeHID:
		return ResolvedProvider{Mode: ModeHID, Provider: p.hid}, nil
	case ModeWindowsProxy:
		if err := p.proxy.Check(ctx); err != nil {
			return ResolvedProvider{}, proxyUnavailableError(err)
		}

		return ResolvedProvider{Mode: ModeWindowsProxy, Provider: p.proxy}, nil
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

type proxyProvider struct{}

func (proxyProvider) Check(ctx context.Context) error {
	_, err := proxyDescriptors(ctx)

	return err
}

func (proxyProvider) List(ctx context.Context) ([]Descriptor, error) {
	return proxyDescriptors(ctx)
}

func proxyDescriptors(ctx context.Context) ([]Descriptor, error) {
	infos, err := discover.EnumerateFIDODevices(
		ctx,
		options.WithUseNamedPipes(),
	)
	if err != nil {
		return nil, proxyUnavailableError(err)
	}

	return descriptorsFromDeviceInfos(ModeWindowsProxy, infos), nil
}
