//go:build windows

package transport

import (
	"context"
	"fmt"

	"github.com/go-ctap/ctaphid/pkg/options"
	"github.com/go-ctap/ctaphid/pkg/sugar"
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
			return ResolvedProvider{}, fmt.Errorf("%w: run elevated or start the proxy service: %v", ErrProxyUnavailable, err)
		}

		return ResolvedProvider{Mode: ModeWindowsProxy, Provider: p.proxy}, nil
	case ModeHID:
		return ResolvedProvider{Mode: ModeHID, Provider: p.hid}, nil
	case ModeWindowsProxy:
		if err := p.proxy.Check(ctx); err != nil {
			return ResolvedProvider{}, fmt.Errorf("%w: start the proxy service for windows-proxy mode: %v", ErrProxyUnavailable, err)
		}

		return ResolvedProvider{Mode: ModeWindowsProxy, Provider: p.proxy}, nil
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

type proxyProvider struct{}

func (proxyProvider) Check(ctx context.Context) error {
	_, err := proxyDescriptors(ctx)

	return err
}

func (proxyProvider) List(ctx context.Context) ([]Descriptor, error) {
	return proxyDescriptors(ctx)
}

func proxyDescriptors(ctx context.Context) ([]Descriptor, error) {
	infos, err := sugar.EnumerateFIDODevices(
		options.WithContext(ctx),
		options.WithUseNamedPipes(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProxyUnavailable, err)
	}

	return descriptorsFromDeviceInfos(ModeWindowsProxy, infos), nil
}
