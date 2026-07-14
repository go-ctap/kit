//go:build windows

package transport

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

type fakeProvider struct {
	checkErr   error
	list       []Descriptor
	listErr    error
	checkCount int
}

func (f *fakeProvider) Check(context.Context) error {
	f.checkCount++

	return f.checkErr
}

func (f *fakeProvider) List(context.Context) ([]Descriptor, error) {
	return f.list, f.listErr
}

func TestTransportPolicyAutoElevated(t *testing.T) {
	hid := &fakeProvider{}
	proxy := &fakeProvider{}
	resolver := windowsPolicy{hid: hid, proxy: proxy, isElevated: func() bool { return true }}

	resolved, err := resolver.Resolve(context.Background(), ModeAuto)
	if err != nil {
		t.Fatalf("Resolve(auto,elevated): %v", err)
	}

	if resolved.Mode != ModeHID {
		t.Fatalf("resolved mode = %q, want %q", resolved.Mode, ModeHID)
	}

	if resolved.Provider != hid {
		t.Fatalf("expected HID provider to be selected")
	}

	if proxy.checkCount != 0 {
		t.Fatalf("proxy check count = %d, want 0", proxy.checkCount)
	}
}

func TestTransportPolicyAutoProxyFallback(t *testing.T) {
	hid := &fakeProvider{}
	proxy := &fakeProvider{}
	resolver := windowsPolicy{hid: hid, proxy: proxy, isElevated: func() bool { return false }}

	resolved, err := resolver.Resolve(context.Background(), ModeAuto)
	if err != nil {
		t.Fatalf("Resolve(auto,unelevated): %v", err)
	}

	if resolved.Mode != ModeWindowsProxy {
		t.Fatalf("resolved mode = %q, want %q", resolved.Mode, ModeWindowsProxy)
	}

	if resolved.Provider != proxy {
		t.Fatalf("expected proxy provider to be selected")
	}

	if proxy.checkCount != 1 {
		t.Fatalf("proxy check count = %d, want 1", proxy.checkCount)
	}
}

func TestTransportPolicyProxyUnavailable(t *testing.T) {
	hid := &fakeProvider{}
	proxy := &fakeProvider{checkErr: errors.New("pipe unavailable")}
	resolver := windowsPolicy{hid: hid, proxy: proxy, isElevated: func() bool { return false }}

	_, err := resolver.Resolve(context.Background(), ModeAuto)
	if err == nil {
		t.Fatal("Resolve(auto,proxy unavailable) returned nil error")
	}

	if !failure.IsCode(err, failure.CodeTransportProxyUnavailable) {
		t.Fatalf("Resolve error = %v, want %s", err, failure.CodeTransportProxyUnavailable)
	}
}
