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
	open := func(context.Context, transport.Mode, string) (any, error) {
		opens++

		return &contractAuthenticator{}, nil
	}
	device := newContractDevice()

	first, err := openAuthenticatorHandle(t.Context(), device, adaptContractAuthenticatorOpen(open))
	if err != nil {
		t.Fatalf("open first opened: %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("close first opened: %v", err)
		}
	}()

	second, err := openAuthenticatorHandle(t.Context(), device, adaptContractAuthenticatorOpen(open))
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
	open := func(ctx context.Context, _ transport.Mode, _ string) (any, error) {
		kitlog.RecorderFrom(ctx).Append(model.LogEntry{Command: "open-command"})

		return &contractAuthenticator{}, nil
	}

	opened, err := openAuthenticatorHandle(
		t.Context(),
		newContractDevice(),
		adaptContractAuthenticatorOpen(open),
		WithLogJournal(journal),
	)
	if err != nil {
		t.Fatalf("OpenAuthenticator: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	batch := journal.Read(0)
	if len(batch.Entries) != 1 || batch.Entries[0].Entry.Command != "open-command" {
		t.Fatalf("open log entries = %#v", batch.Entries)
	}
}

func TestContractAuthenticatorBaseExposesOnlyRuntimeCapabilities(t *testing.T) {
	opened := adaptContractAuthenticator(&contractAuthenticator{})

	if opened.Lifecycle == nil || opened.Info == nil || opened.Tokens == nil || opened.ConfigStatus == nil {
		t.Fatalf("runtime capabilities are incomplete: %#v", opened)
	}
	if opened.CredentialInventory != nil || opened.Credentials != nil || opened.WebAuthn != nil ||
		opened.LargeBlobs != nil || opened.Config != nil || opened.Bio != nil {
		t.Fatalf("base fake exposes unrelated domain capabilities: %#v", opened)
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

type contractAuthenticatorOpenFunc func(context.Context, transport.Mode, string) (any, error)

func openContractAuthenticator(
	t *testing.T,
	events EventSink,
	implementation any,
	opts ...AuthenticatorOption,
) *contractAuthenticatorHandle {
	t.Helper()

	if implementation == nil {
		implementation = &contractAuthenticator{}
	}

	opened, err := openAuthenticatorHandle(
		context.Background(),
		newContractDevice(),
		func(context.Context, transport.Mode, string) (*authenticator.Opened, error) {
			return adaptContractAuthenticator(implementation), nil
		},
		opts...,
	)
	if err != nil {
		t.Fatalf("OpenAuthenticator: %v", err)
	}

	return &contractAuthenticatorHandle{Authenticator: opened, events: events}
}

func adaptContractAuthenticatorOpen(open contractAuthenticatorOpenFunc) authenticatorOpenFunc {
	return func(ctx context.Context, mode transport.Mode, path string) (*authenticator.Opened, error) {
		implementation, err := open(ctx, mode, path)
		if err != nil {
			return nil, err
		}

		return adaptContractAuthenticator(implementation), nil
	}
}

func adaptContractAuthenticator(implementation any) *authenticator.Opened {
	if opened, ok := implementation.(*authenticator.Opened); ok {
		return opened
	}

	opened := &authenticator.Opened{}
	opened.Lifecycle, _ = implementation.(authenticator.Lifecycle)
	opened.Info, _ = implementation.(authenticator.InfoProvider)
	opened.Tokens, _ = implementation.(authenticator.TokenProvider)
	opened.CredentialInventory, _ = implementation.(authenticator.CredentialInventoryReader)
	opened.Credentials, _ = implementation.(authenticator.CredentialManager)
	opened.WebAuthn, _ = implementation.(authenticator.WebAuthnManager)
	opened.LargeBlobs, _ = implementation.(authenticator.LargeBlobDevice)
	opened.ConfigStatus, _ = implementation.(authenticator.ConfigStatusDevice)
	opened.Config, _ = implementation.(authenticator.ConfigDevice)
	opened.Bio, _ = implementation.(authenticator.BioDevice)

	return opened
}

func newContractDevice() Device {
	return newDevice(0, transport.ModeHID, transport.Descriptor{
		Path:      "contract-path",
		VendorID:  1,
		ProductID: 2,
	})
}
