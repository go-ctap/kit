package device

import (
	"regexp"
	"testing"

	"github.com/go-ctap/kit/transport"
)

func TestFingerprint(t *testing.T) {
	base := transport.Descriptor{
		Transport: transport.ModeHID,
		Path:      "hid://path-a",
		Serial:    "12345678",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	fingerprint := Fingerprint(base)

	if matched := regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fingerprint); !matched {
		t.Fatalf("fingerprint %q does not match expected lowercase hex shape", fingerprint)
	}

	if got := len(fingerprint); got != fingerprintLength {
		t.Fatalf("fingerprint length = %d, want %d", got, fingerprintLength)
	}

	tests := []struct {
		name     string
		mode     transport.Mode
		path     string
		serial   string
		product  uint16
		wantSame bool
	}{
		{name: "transport attachment ignored", mode: transport.ModeWindowsProxy, path: "hid://path-b", serial: "12345678", product: 0x0407, wantSame: true},
		{name: "serial distinguishes device", mode: transport.ModeHID, path: "hid://path-a", serial: "87654321", product: 0x0407},
		{name: "product distinguishes device", mode: transport.ModeHID, path: "hid://path-a", serial: "12345678", product: 0x0408},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := transport.Descriptor{
				Transport: test.mode,
				Path:      test.path,
				Serial:    test.serial,
				VendorID:  base.VendorID,
				ProductID: test.product,
			}
			got := Fingerprint(descriptor)
			if same := got == fingerprint; same != test.wantSame {
				t.Fatalf("fingerprint = %q, base = %q, same = %v, want %v", got, fingerprint, same, test.wantSame)
			}
		})
	}
}

func TestFingerprintFallsBackToTransportAttachmentWithoutSerial(t *testing.T) {
	descriptor := transport.Descriptor{
		Transport: transport.ModeHID,
		Path:      "hid://path-a",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	fingerprint := Fingerprint(descriptor)

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
			got := Fingerprint(descriptor)
			if same := got == fingerprint; same != test.wantSame {
				t.Fatalf("fingerprint = %q, base = %q, same = %v, want %v", got, fingerprint, same, test.wantSame)
			}
		})
	}
}

func TestFingerprintDistinguishesSmartCardATR(t *testing.T) {
	first := transport.Descriptor{
		Transport: transport.ModeSmartCard,
		Path:      "PC/SC Reader",
		ATR:       []byte{0x01},
	}
	second := first
	second.ATR = []byte{0x02}

	if Fingerprint(first) == Fingerprint(second) {
		t.Fatal("fingerprints for different smart-card ATRs collide")
	}
}
