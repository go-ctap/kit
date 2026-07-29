package device

import (
	"regexp"
	"testing"

	"github.com/go-ctap/kit/internal/discovery"
	"github.com/go-ctap/kit/transport"
)

func TestAttachmentID(t *testing.T) {
	base := discovery.Descriptor{
		Transport: transport.ModeHID,
		Path:      "hid://path-a",
		Serial:    "12345678",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	attachmentID := AttachmentID(base)

	if matched := regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(attachmentID); !matched {
		t.Fatalf("attachment ID %q does not match expected lowercase hex shape", attachmentID)
	}

	if got := len(attachmentID); got != attachmentIDLength {
		t.Fatalf("attachment ID length = %d, want %d", got, attachmentIDLength)
	}

	tests := []struct {
		name     string
		mode     transport.Mode
		path     string
		serial   string
		product  uint16
		wantSame bool
	}{
		{name: "serial ignored", mode: transport.ModeHID, path: "hid://path-a", serial: "87654321", product: 0x0407, wantSame: true},
		{name: "product ignored", mode: transport.ModeHID, path: "hid://path-a", serial: "12345678", product: 0x0408, wantSame: true},
		{name: "path distinguishes endpoint", mode: transport.ModeHID, path: "hid://path-b", serial: "12345678", product: 0x0407},
		{name: "transport distinguishes endpoint", mode: transport.ModeWindowsProxy, path: "hid://path-a", serial: "12345678", product: 0x0407},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := discovery.Descriptor{
				Transport: test.mode,
				Path:      test.path,
				Serial:    test.serial,
				VendorID:  base.VendorID,
				ProductID: test.product,
			}
			got := AttachmentID(descriptor)
			if same := got == attachmentID; same != test.wantSame {
				t.Fatalf("attachment ID = %q, base = %q, same = %v, want %v", got, attachmentID, same, test.wantSame)
			}
		})
	}
}

func TestAttachmentIDNormalizesEndpoint(t *testing.T) {
	descriptor := discovery.Descriptor{
		Transport: transport.ModeHID,
		Path:      "hid://path-a",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	attachmentID := AttachmentID(descriptor)

	tests := []struct {
		name     string
		mode     transport.Mode
		path     string
		wantSame bool
	}{
		{name: "normalizes path", mode: transport.ModeHID, path: " hid://path-a ", wantSame: true},
		{name: "path distinguishes attachment", mode: transport.ModeHID, path: "hid://path-b"},
		{name: "mode distinguishes attachment", mode: transport.ModeWindowsProxy, path: "hid://path-a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor.Transport = test.mode
			descriptor.Path = test.path
			got := AttachmentID(descriptor)
			if same := got == attachmentID; same != test.wantSame {
				t.Fatalf("attachment ID = %q, base = %q, same = %v, want %v", got, attachmentID, same, test.wantSame)
			}
		})
	}
}

func TestAttachmentIDIgnoresSmartCardATR(t *testing.T) {
	first := discovery.Descriptor{
		Transport:          transport.ModeSmartCard,
		Path:               "PC/SC Reader",
		ATR:                []byte{0x01},
		SmartCardInterface: transport.SmartCardInterfaceContact,
	}
	second := first
	second.ATR = []byte{0x02}

	if AttachmentID(first) != AttachmentID(second) {
		t.Fatal("attachment ID changed with the card ATR")
	}
}

func TestAttachmentIDDistinguishesSmartCardInterface(t *testing.T) {
	contact := discovery.Descriptor{
		Transport:          transport.ModeSmartCard,
		Path:               "PC/SC Reader",
		SmartCardInterface: transport.SmartCardInterfaceContact,
	}
	contactless := contact
	contactless.SmartCardInterface = transport.SmartCardInterfaceContactless

	if AttachmentID(contact) == AttachmentID(contactless) {
		t.Fatal("attachment ID did not change with the smart-card interface")
	}
}
