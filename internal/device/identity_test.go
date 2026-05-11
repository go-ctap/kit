package device

import (
	"regexp"
	"testing"
)

func TestID(t *testing.T) {
	serialID := ID(0x1050, 0x0407, "12345678", "hid://path-a")

	if matched := regexp.MustCompile(`^[a-z2-7]{6}$`).MatchString(serialID); !matched {
		t.Fatalf("device id %q does not match expected lowercase base32 shape", serialID)
	}

	if got := len(serialID); got != 6 {
		t.Fatalf("device id length = %d, want 6", got)
	}

	if movedID := ID(0x1050, 0x0407, "12345678", "hid://path-b"); movedID != serialID {
		t.Fatalf("serial-backed id should ignore path changes: %q != %q", movedID, serialID)
	}

	fallbackID := ID(0x1050, 0x0407, "", "hid://fallback-a")
	if fallbackID == serialID {
		t.Fatalf("fallback id should differ from serial-backed id: %q", fallbackID)
	}

	if samePathID := ID(0x1050, 0x0407, "", "hid://fallback-a"); samePathID != fallbackID {
		t.Fatalf("path fallback id should be stable for same path: %q != %q", samePathID, fallbackID)
	}

	if changedPathID := ID(0x1050, 0x0407, "", "hid://fallback-b"); changedPathID == fallbackID {
		t.Fatalf("path fallback id should change when path changes: %q", changedPathID)
	}
}

func TestStable(t *testing.T) {
	if !Stable(0x1050, 0x0407, "12345678", "hid://path-a") {
		t.Fatal("serial-backed identity should be stable")
	}

	if Stable(0x1050, 0x0407, "", "hid://fallback-a") {
		t.Fatal("path-backed identity should not be stable")
	}
}
