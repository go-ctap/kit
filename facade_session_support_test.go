package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/internal/authenticator"
	kitlog "github.com/go-ctap/kit/internal/logging"
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

	first, err := openSession(t.Context(), device, open)
	if err != nil {
		t.Fatalf("open first session: %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("close first session: %v", err)
		}
	}()

	second, err := openSession(t.Context(), device, open)
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

func TestOpenSessionMakesJournalAvailableWhileOpeningAuthenticator(t *testing.T) {
	journal := NewLogJournal()
	open := func(ctx context.Context, _ transport.Mode, _ string) (authenticator.Device, error) {
		kitlog.RecorderFrom(ctx).Append(model.LogEntry{Code: "open-command"})

		return &contractAuthenticator{}, nil
	}
	session := openContractSessionWithOptions(t, nil, open, WithLogJournal(journal))
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	batch := journal.Read(0)
	if len(batch.Entries) != 1 || batch.Entries[0].Entry.Code != "open-command" {
		t.Fatalf("open log entries = %#v", batch.Entries)
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
	if open == nil {
		open = func(context.Context, transport.Mode, string) (authenticator.Device, error) {
			return &contractAuthenticator{}, nil
		}
	}

	sessionOpts := []OpenSessionOption(nil)
	if events != nil {
		sessionOpts = append(sessionOpts, WithEventSink(events))
	}
	sessionOpts = append(sessionOpts, opts...)

	session, err := openSession(
		context.Background(),
		newContractDevice(),
		open,
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
