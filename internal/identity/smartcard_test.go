package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/kit/internal/discovery"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
	"github.com/go-ctap/token2"
	token2resolver "github.com/go-ctap/token2/resolver"
	"github.com/go-ctap/yubico"
	yubicoresolver "github.com/go-ctap/yubico/resolver"
)

type fakeYubicoIdentityResolver struct {
	info  yubico.DeviceInfo
	err   error
	calls int
}

func (r *fakeYubicoIdentityResolver) ResolveSmartCard(
	context.Context,
	string,
) (yubico.DeviceInfo, error) {
	r.calls++
	return r.info, r.err
}

type fakeToken2IdentityResolver struct {
	smartCardResult token2resolver.Result
	smartCardErr    error
	smartCardCalls  int
}

func (r *fakeToken2IdentityResolver) ResolveSmartCard(
	context.Context,
	string,
) (token2resolver.Result, error) {
	r.smartCardCalls++
	return r.smartCardResult, r.smartCardErr
}

func (*fakeToken2IdentityResolver) ResolveHID(
	context.Context,
	token2resolver.HIDTarget,
) (token2resolver.Result, error) {
	return token2resolver.Result{}, errors.New(
		"unexpected Token2 HID resolution",
	)
}

func TestResolverPrefersYubicoForSmartCards(t *testing.T) {
	nfcSupported := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	yubicoResolver := &fakeYubicoIdentityResolver{
		info: yubico.DeviceInfo{
			SupportedUSBCapabilities: yubico.CapabilityU2F |
				yubico.CapabilityCTAP2,
			EnabledUSBCapabilities: yubico.CapabilityU2F |
				yubico.CapabilityCTAP2,
			FormFactor:               yubico.FormFactorUSBAKeychain,
			FirmwareVersion:          yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1},
			SupportedNFCCapabilities: &nfcSupported,
			EnabledNFCCapabilities:   &nfcSupported,
		},
	}
	token2Resolver := &fakeToken2IdentityResolver{}
	resolver := &Resolver{
		token2: token2Resolver,
		yubico: yubicoResolver,
	}
	descriptor := discovery.Descriptor{
		Transport: transport.ModeSmartCard,
		Path:      "NFC reader",
	}

	if got := resolver.Provider(descriptor); got != report.VendorUnknown {
		t.Fatalf("topology provider = %q, want unknown", got)
	}
	if !resolver.CanResolve(descriptor) {
		t.Fatal("smart card was not scheduled for identity resolution")
	}

	resolution, err := resolver.Resolve(t.Context(), descriptor)
	if err != nil {
		t.Fatalf("resolve Yubico smart card: %v", err)
	}
	if resolution.Provider != report.VendorYubico ||
		resolution.Identity == nil ||
		resolution.Identity.Model != "YubiKey 5 NFC" {
		t.Fatalf("resolution = %#v", resolution)
	}
	if yubicoResolver.calls != 1 {
		t.Fatalf("Yubico resolver calls = %d, want 1", yubicoResolver.calls)
	}
	if token2Resolver.smartCardCalls != 0 {
		t.Fatalf(
			"Token2 resolver calls = %d, want 0",
			token2Resolver.smartCardCalls,
		)
	}
}

func TestResolverFallsBackToToken2ForSmartCards(t *testing.T) {
	identity, known := token2.Identify("66202208969539")
	if !known {
		t.Fatal("Token2 test serial is not in model catalog")
	}
	yubicoResolver := &fakeYubicoIdentityResolver{
		err: yubicoresolver.ErrNotApplicable,
	}
	token2Resolver := &fakeToken2IdentityResolver{
		smartCardResult: token2resolver.Result{
			Identity:   identity,
			ModelKnown: true,
		},
	}
	resolver := &Resolver{
		token2: token2Resolver,
		yubico: yubicoResolver,
	}

	resolution, err := resolver.Resolve(t.Context(), discovery.Descriptor{
		Transport: transport.ModeSmartCard,
		Path:      "contact reader",
	})
	if err != nil {
		t.Fatalf("resolve Token2 smart card: %v", err)
	}
	if resolution.Provider != report.VendorToken2 ||
		resolution.Identity == nil ||
		resolution.Identity.Model == "" {
		t.Fatalf("resolution = %#v", resolution)
	}
	if token2Resolver.smartCardCalls != 1 {
		t.Fatalf(
			"Token2 resolver calls = %d, want 1",
			token2Resolver.smartCardCalls,
		)
	}
}
