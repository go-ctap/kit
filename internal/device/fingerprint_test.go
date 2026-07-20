package device

import (
	"regexp"
	"testing"

	"github.com/go-ctap/kit/transport"
)

func TestFingerprint(t *testing.T) {
	descriptor := transport.Descriptor{
		Path:      "hid://path-a",
		Serial:    "12345678",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	fingerprint := Fingerprint(transport.ModeHID, descriptor)

	if matched := regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fingerprint); !matched {
		t.Fatalf("fingerprint %q does not match expected lowercase hex shape", fingerprint)
	}

	if got := len(fingerprint); got != fingerprintLength {
		t.Fatalf("fingerprint length = %d, want %d", got, fingerprintLength)
	}

	descriptor.Path = "hid://path-b"
	if moved := Fingerprint(transport.ModeWindowsProxy, descriptor); moved != fingerprint {
		t.Fatalf("serial-backed fingerprint changed with transport attachment: %q != %q", moved, fingerprint)
	}

	descriptor.Serial = "87654321"
	if replaced := Fingerprint(transport.ModeHID, descriptor); replaced == fingerprint {
		t.Fatalf("fingerprint did not change with device serial: %q", replaced)
	}

	descriptor.Serial = "12345678"
	descriptor.ProductID = 0x0408
	if anotherProduct := Fingerprint(transport.ModeHID, descriptor); anotherProduct == fingerprint {
		t.Fatalf("fingerprints for different products collide: %q", anotherProduct)
	}
}

func TestFingerprintFallsBackToTransportAttachmentWithoutSerial(t *testing.T) {
	descriptor := transport.Descriptor{
		Path:      "hid://path-a",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	fingerprint := Fingerprint(transport.ModeHID, descriptor)

	descriptor.Path = " hid://path-a "
	if repeated := Fingerprint(transport.ModeHID, descriptor); repeated != fingerprint {
		t.Fatalf("fingerprint changed for the same normalized path: %q != %q", repeated, fingerprint)
	}

	descriptor.Path = "hid://path-b"
	if moved := Fingerprint(transport.ModeHID, descriptor); moved == fingerprint {
		t.Fatalf("path-backed fingerprint did not change with transport path: %q", moved)
	}

	descriptor.Path = "hid://path-a"
	if proxy := Fingerprint(transport.ModeWindowsProxy, descriptor); proxy == fingerprint {
		t.Fatalf("path-backed fingerprints for different transports collide: %q", proxy)
	}
}
