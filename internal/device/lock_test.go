package device

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func TestLeaseLocking(t *testing.T) {
	tempDir := t.TempDir()
	originalUserCacheDir := userCacheDir
	userCacheDir = func() (string, error) { return tempDir, nil }

	defer func() { userCacheDir = originalUserCacheDir }()

	device := report.DeviceReport{
		DeviceID:     ID(0x1050, 0x0407, "12345678", "hid://one"),
		OrdinalAlias: "1",
		StableID:     true,
		Transport:    transport.ModeHID,
		Path:         "hid://one",
		Manufacturer: "Yubico",
		Product:      "YubiKey 5C NFC",
		Serial:       "12345678",
		VendorID:     0x1050,
		ProductID:    0x0407,
	}

	lease, err := AcquireLease(context.Background(), device)
	if err != nil {
		t.Fatalf("Acquire(first): %v", err)
	}

	key := Key(device.VendorID, device.ProductID, device.Serial, device.Path)
	wantLockPath := filepath.Join(tempDir, lockNamespace, lockDirName, key+".lock")
	if got := lease.Path(); got != wantLockPath {
		t.Fatalf("lock path = %q, want %q", got, wantLockPath)
	}

	if err := lease.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}

	if err := lease.Close(); err != nil {
		t.Fatalf("Close(first again): %v", err)
	}

	reacquired, err := AcquireLease(context.Background(), device)
	if err != nil {
		t.Fatalf("Acquire(second): %v", err)
	}

	if err := reacquired.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}
}

func TestDeviceBusy(t *testing.T) {
	tempDir := t.TempDir()
	originalUserCacheDir := userCacheDir
	userCacheDir = func() (string, error) { return tempDir, nil }

	defer func() { userCacheDir = originalUserCacheDir }()

	device := report.DeviceReport{
		DeviceID:  ID(0x1050, 0x0408, "87654321", "hid://busy"),
		Path:      "hid://busy",
		Serial:    "87654321",
		VendorID:  0x1050,
		ProductID: 0x0408,
	}

	lease, err := AcquireLease(context.Background(), device)
	if err != nil {
		t.Fatalf("Acquire(holder): %v", err)
	}

	defer func() {
		if err := lease.Close(); err != nil {
			t.Fatalf("Close(holder): %v", err)
		}
	}()

	_, err = AcquireLease(context.Background(), device)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("Acquire(contender) error = %v, want ErrBusy", err)
	}
}

func TestSerialBackedDevicesShareLeaseAcrossPathChanges(t *testing.T) {
	tempDir := t.TempDir()
	originalUserCacheDir := userCacheDir
	userCacheDir = func() (string, error) { return tempDir, nil }

	defer func() { userCacheDir = originalUserCacheDir }()

	first := report.DeviceReport{
		DeviceID:  ID(0x1050, 0x0407, "12345678", "hid://serial-a"),
		Path:      "hid://serial-a",
		Serial:    "12345678",
		VendorID:  0x1050,
		ProductID: 0x0407,
	}
	second := first
	second.Path = "hid://serial-b"

	firstLease, err := AcquireLease(context.Background(), first)
	if err != nil {
		t.Fatalf("Acquire(first): %v", err)
	}
	defer func() {
		if err := firstLease.Close(); err != nil {
			t.Fatalf("Close(first): %v", err)
		}
	}()

	_, err = AcquireLease(context.Background(), second)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("Acquire(second path) error = %v, want ErrBusy", err)
	}
}
