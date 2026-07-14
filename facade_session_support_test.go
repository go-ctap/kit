package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/transport"
)

func TestOpenSessionAllowsIndependentChannelsForSameDevice(t *testing.T) {
	opens := 0
	open := func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		opens++

		return &contractAuthenticator{}, nil
	}
	device := newContractDevice()
	deps := newContractSessionDependencies(open)

	first, err := openSession(t.Context(), device, deps)
	if err != nil {
		t.Fatalf("open first session: %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("close first session: %v", err)
		}
	}()

	second, err := openSession(t.Context(), device, deps)
	if err != nil {
		t.Fatalf("open second session: %v", err)
	}
	defer func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second session: %v", err)
		}
	}()

	if opens != 2 {
		t.Fatalf("authenticator opens = %d, want 2", opens)
	}
}

func newContractSessionDependencies(open authenticatorOpenFunc) sessionDependencies {
	if open == nil {
		open = func(context.Context, transport.Mode, string) (authenticator.Device, error) {
			return &contractAuthenticator{}, nil
		}
	}

	return sessionDependencies{
		openAuthenticator: open,
	}
}

func openContractSession(t *testing.T, events model.EventSink, open authenticatorOpenFunc) *Session {
	return openContractSessionWithOptions(t, events, open)
}

func openContractSessionWithOptions(
	t *testing.T,
	events model.EventSink,
	open authenticatorOpenFunc,
	opts ...OpenSessionOption,
) *Session {
	t.Helper()

	sessionOpts := []OpenSessionOption(nil)
	if events != nil {
		sessionOpts = append(sessionOpts, WithEventSink(events))
	}
	sessionOpts = append(sessionOpts, opts...)

	session, err := openSession(
		context.Background(),
		newContractDevice(),
		newContractSessionDependencies(open),
		sessionOpts...,
	)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	return session
}

func newContractDevice() Device {
	return newDevice(0, transport.ModeHID, transport.Descriptor{
		Transport: transport.ModeHID,
		Path:      "contract-path",
		VendorID:  1,
		ProductID: 2,
	})
}
