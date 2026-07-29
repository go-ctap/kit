package discovery

import (
	"context"
	"errors"
	"testing"

	ctapiso7816 "github.com/go-ctap/ctap/transport/iso7816"
	baseiso7816 "github.com/go-ctap/iso7816"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
	"github.com/go-ctap/pcsc"
)

func TestSmartCardClassification(t *testing.T) {
	if !isNonFIDOCard(&baseiso7816.APDUError{SW1: 0x6a, SW2: 0x82}) {
		t.Fatal("missing FIDO applet was not classified as a non-FIDO card")
	}
	if !isNonFIDOCard(ctapiso7816.ErrUnsupportedVersion) {
		t.Fatal("unsupported applet version was not classified as a non-FIDO card")
	}
	if isNonFIDOCard(errors.New("reader disconnected")) {
		t.Fatal("reader failure was classified as a non-FIDO card")
	}
}

func TestSmartCardFailureCode(t *testing.T) {
	if got := failureCodeForSmartCard(pcsc.ErrNoAccess); got != failure.CodeTransportPermissionDenied {
		t.Fatalf("permission code = %q, want %q", got, failure.CodeTransportPermissionDenied)
	}
	if got := failureCodeForSmartCard(pcsc.ErrNoService); got != failure.CodeTransportFailure {
		t.Fatalf("transport code = %q, want %q", got, failure.CodeTransportFailure)
	}
}

func TestSmartCardInterface(t *testing.T) {
	tests := []struct {
		name  string
		value pcsc.CardInterface
		want  transport.SmartCardInterface
	}{
		{
			name:  "contact",
			value: pcsc.CardInterfaceContact,
			want:  transport.SmartCardInterfaceContact,
		},
		{
			name:  "contactless",
			value: pcsc.CardInterfaceContactless,
			want:  transport.SmartCardInterfaceContactless,
		},
		{
			name:  "unknown",
			value: pcsc.CardInterfaceUnknown,
			want:  transport.SmartCardInterfaceUnknown,
		},
		{
			name:  "future value",
			value: pcsc.CardInterface("future"),
			want:  transport.SmartCardInterfaceUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := smartCardInterface(tt.value); got != tt.want {
				t.Fatalf("interface = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSmartCardDescriptorKeepsReaderOutOfCardIdentity(t *testing.T) {
	reader := pcsc.ReaderInfo{
		Name: "Token2 Smart Reader",
		ATR:  []byte{0x01, 0x02},
	}

	descriptor := smartCardDescriptor(reader, transport.SmartCardInterfaceContactless)
	if descriptor.Transport != ModeSmartCard ||
		descriptor.Path != reader.Name ||
		descriptor.Product != "" ||
		descriptor.SmartCardInterface != transport.SmartCardInterfaceContactless ||
		string(descriptor.ATR) != string(reader.ATR) {
		t.Fatalf("descriptor = %#v", descriptor)
	}
}

func TestSmartCardDiscoveryRetainsKnownExclusiveCard(t *testing.T) {
	discovery := &smartCardDiscovery{}
	reader := pcsc.ReaderInfo{
		Name:  "reader-one",
		State: pcsc.ReaderStatePresent,
		ATR:   []byte{0x01, 0x02},
	}
	probes := 0
	probe := func(context.Context, string) (transport.SmartCardInterface, error) {
		probes++

		return transport.SmartCardInterfaceUnknown, nil
	}

	first, err := discovery.discover(t.Context(), []pcsc.ReaderInfo{reader}, probe)
	if err != nil {
		t.Fatalf("initial discovery: %v", err)
	}
	if len(first) != 1 ||
		first[0].SmartCardInterface != transport.SmartCardInterfaceUnknown ||
		probes != 1 {
		t.Fatalf("initial descriptors = %#v, probes = %d", first, probes)
	}

	reader.State |= pcsc.ReaderStateExclusive
	reader.ATR = nil
	second, err := discovery.discover(t.Context(), []pcsc.ReaderInfo{reader}, func(
		context.Context,
		string,
	) (transport.SmartCardInterface, error) {
		t.Fatal("exclusive known card was probed again")

		return transport.SmartCardInterfaceUnknown, nil
	})
	if err != nil {
		t.Fatalf("exclusive discovery: %v", err)
	}
	if len(second) != 1 ||
		second[0].Transport != ModeSmartCard ||
		second[0].Path != reader.Name ||
		len(second[0].ATR) != 2 {
		t.Fatalf("exclusive descriptors = %#v", second)
	}
}

func TestSmartCardDiscoveryRetainsKnownCardAfterSharingViolation(t *testing.T) {
	discovery := &smartCardDiscovery{}
	reader := pcsc.ReaderInfo{
		Name:  "reader-one",
		State: pcsc.ReaderStatePresent,
		ATR:   []byte{0x01, 0x02},
	}

	_, err := discovery.discover(t.Context(), []pcsc.ReaderInfo{reader}, func(
		context.Context,
		string,
	) (transport.SmartCardInterface, error) {
		return transport.SmartCardInterfaceUnknown, nil
	})
	if err != nil {
		t.Fatalf("initial discovery: %v", err)
	}

	descriptors, err := discovery.discover(t.Context(), []pcsc.ReaderInfo{reader}, func(
		context.Context,
		string,
	) (transport.SmartCardInterface, error) {
		return "", pcsc.ErrSharingViolation
	})
	if err != nil {
		t.Fatalf("sharing discovery: %v", err)
	}
	if len(descriptors) != 1 || descriptors[0].Path != reader.Name {
		t.Fatalf("sharing descriptors = %#v", descriptors)
	}
}

func TestSmartCardDiscoveryForgetsRemovedCard(t *testing.T) {
	discovery := &smartCardDiscovery{}
	reader := pcsc.ReaderInfo{
		Name:  "reader-one",
		State: pcsc.ReaderStatePresent,
		ATR:   []byte{0x01, 0x02},
	}

	_, err := discovery.discover(t.Context(), []pcsc.ReaderInfo{reader}, func(
		context.Context,
		string,
	) (transport.SmartCardInterface, error) {
		return transport.SmartCardInterfaceUnknown, nil
	})
	if err != nil {
		t.Fatalf("initial discovery: %v", err)
	}
	if descriptors, err := discovery.discover(t.Context(), nil, nil); err != nil || len(descriptors) != 0 {
		t.Fatalf("empty discovery descriptors = %#v, error = %v", descriptors, err)
	}

	reader.State |= pcsc.ReaderStateExclusive
	descriptors, err := discovery.discover(t.Context(), []pcsc.ReaderInfo{reader}, func(
		context.Context,
		string,
	) (transport.SmartCardInterface, error) {
		return "", pcsc.ErrSharingViolation
	})
	if err == nil {
		t.Fatal("forgotten exclusive card did not require a successful probe")
	}
	if len(descriptors) != 0 {
		t.Fatalf("forgotten descriptors = %#v", descriptors)
	}
}
