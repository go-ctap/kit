package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/transport"
)

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
