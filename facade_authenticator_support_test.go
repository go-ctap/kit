package ctapkit

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/discovery"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func requireZero[T any](t *testing.T, value T) {
	t.Helper()

	var zero T
	if !reflect.DeepEqual(value, zero) {
		t.Fatalf("value = %#v, want zero value", value)
	}
}

func TestOpenAuthenticatorAllowsIndependentChannelsForSameDevice(t *testing.T) {
	opens := 0
	open := func(context.Context, transport.Mode, string) (*authenticator.Opened, error) {
		opens++

		return contractOpened(&contractAuthenticator{}), nil
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
	open := func(ctx context.Context, _ transport.Mode, _ string) (*authenticator.Opened, error) {
		kitlog.RecorderFrom(ctx).Append(model.LogEntry{Command: "open-command"})

		return contractOpened(&contractAuthenticator{}), nil
	}

	opened, err := openAuthenticatorHandle(
		t.Context(),
		newContractDevice(),
		open,
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

type contractAuthenticatorHandle struct {
	*Authenticator
	events EventSink
}

type contractDevice interface {
	authenticator.Lifecycle
	authenticator.InfoProvider
	authenticator.VendorProvider
	authenticator.TokenProvider
	authenticator.CredentialInventoryReader
	authenticator.CredentialManager
	authenticator.WebAuthnManager
	authenticator.LargeBlobDevice
	authenticator.ConfigStatusDevice
	authenticator.ConfigDevice
	authenticator.BioDevice
}

func (a *contractAuthenticatorHandle) operationOptions(opts ...OperationOption) []OperationOption {
	if a.events != nil {
		opts = append(opts, WithEventSink(a.events))
	}

	return opts
}

func openContractAuthenticator(
	t *testing.T,
	events EventSink,
	implementation contractDevice,
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
			return contractOpened(implementation), nil
		},
		opts...,
	)
	if err != nil {
		t.Fatalf("OpenAuthenticator: %v", err)
	}

	return &contractAuthenticatorHandle{Authenticator: opened, events: events}
}

func contractOpened(implementation contractDevice) *authenticator.Opened {
	return &authenticator.Opened{
		Lifecycle:           implementation,
		Info:                implementation,
		Vendor:              implementation,
		Tokens:              implementation,
		CredentialInventory: implementation,
		Credentials:         implementation,
		WebAuthn:            implementation,
		LargeBlobs:          implementation,
		ConfigStatus:        implementation,
		Config:              implementation,
		Bio:                 implementation,
	}
}

func newContractDevice() attachment {
	descriptor := discovery.Descriptor{
		Transport: transport.ModeHID,
		Path:      "contract-path",
		VendorID:  1,
		ProductID: 2,
	}
	return attachment{
		descriptor: descriptor,
		report: report.DeviceReport{
			Attachment: attachmentReport(descriptor),
			Resolution: report.IdentityResolution{State: report.IdentityUnavailable},
		},
	}
}
