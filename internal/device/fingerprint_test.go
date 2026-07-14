package device

import (
	"regexp"
	"testing"

	"github.com/go-ctap/kit/transport"
)

func TestFingerprint(t *testing.T) {
	fingerprint := Fingerprint(transport.ModeHID, "hid://path-a")

	if matched := regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fingerprint); !matched {
		t.Fatalf("fingerprint %q does not match expected lowercase hex shape", fingerprint)
	}

	if got := len(fingerprint); got != fingerprintLength {
		t.Fatalf("fingerprint length = %d, want %d", got, fingerprintLength)
	}

	if repeated := Fingerprint(transport.ModeHID, " hid://path-a "); repeated != fingerprint {
		t.Fatalf("fingerprint changed for the same normalized path: %q != %q", repeated, fingerprint)
	}

	if repathed := Fingerprint(transport.ModeHID, "hid://path-b"); repathed == fingerprint {
		t.Fatalf("fingerprint did not change with transport path: %q", repathed)
	}

	if proxy := Fingerprint(transport.ModeWindowsProxy, "hid://path-a"); proxy == fingerprint {
		t.Fatalf("fingerprints for different transports collide: %q", proxy)
	}
}
