package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/internal/authenticator"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/transport"
)

func TestOpenAuthenticatorAllowsIndependentChannelsForSameDevice(t *testing.T) {
	opens := 0
	open := func(context.Context, transport.Mode, string) (authenticator.Device, error) {
		opens++

		return &contractAuthenticator{}, nil
	}
	device := newContractDevice()

	first, err := openAuthenticatorHandle(t.Context(), device, open)
	if err != nil {
		t.Fatalf("open first opened: %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("close first opened: %v", err)
		}
	}()

	second, err := openAuthenticatorHandle(t.Context(), device, open)
	if err != nil {
		t.Fatalf("open second opened: %v", err)
	}
	defer func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second opened: %v", err)
		}
	}()

	if opens != 2 {
		t.Fatalf("authenticator opens = %d, want 2", opens)
	}
}

func TestOpenAuthenticatorMakesJournalAvailableWhileOpeningAuthenticator(t *testing.T) {
	journal := NewLogJournal()
	open := func(ctx context.Context, _ transport.Mode, _ string) (authenticator.Device, error) {
		kitlog.RecorderFrom(ctx).Append(model.LogEntry{Command: "open-command"})

		return &contractAuthenticator{}, nil
	}

	opened := openContractAuthenticatorWithOptions(t, nil, open, WithLogJournal(journal))
	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	batch := journal.Read(0)
	if len(batch.Entries) != 1 || batch.Entries[0].Entry.Command != "open-command" {
		t.Fatalf("open log entries = %#v", batch.Entries)
	}
}

type contractAuthenticatorHandle struct {
	*Authenticator
	events EventSink
}

func (a *contractAuthenticatorHandle) operationOptions(opts ...OperationOption) []OperationOption {
	if a.events != nil {
		opts = append(opts, WithEventSink(a.events))
	}

	return opts
}

func openContractAuthenticator(t *testing.T, events EventSink, open authenticatorOpenFunc) *contractAuthenticatorHandle {
	return openContractAuthenticatorWithOptions(t, events, open)
}

func openContractAuthenticatorWithOptions(
	t *testing.T,
	events EventSink,
	open authenticatorOpenFunc,
	opts ...AuthenticatorOption,
) *contractAuthenticatorHandle {
	t.Helper()

	if open == nil {
		open = func(context.Context, transport.Mode, string) (authenticator.Device, error) {
			return &contractAuthenticator{}, nil
		}
	}

	opened, err := openAuthenticatorHandle(
		context.Background(),
		newContractDevice(),
		open,
		opts...,
	)
	if err != nil {
		t.Fatalf("OpenAuthenticator: %v", err)
	}

	return &contractAuthenticatorHandle{Authenticator: opened, events: events}
}

func newContractDevice() Device {
	return newDevice(0, transport.ModeHID, transport.Descriptor{
		Path:      "contract-path",
		VendorID:  1,
		ProductID: 2,
	})
}
