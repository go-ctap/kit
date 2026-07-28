package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/ctap/options"
	ghid "github.com/go-ctap/hid"
)

func TestDiscoveryOptionsFollowResolvedMode(t *testing.T) {
	if options.NewOptions(discoveryOptions(ModeHID)...).UseNamedPipe {
		t.Fatal("HID discovery enabled named pipes")
	}

	if !options.NewOptions(discoveryOptions(ModeWindowsProxy)...).UseNamedPipe {
		t.Fatal("Windows proxy discovery did not enable named pipes")
	}
}

func TestDescriptorsRetainConcreteTransport(t *testing.T) {
	descriptors := descriptorsFromDeviceInfos(ModeWindowsProxy, []*ghid.DeviceInfo{{
		Path:       "proxy://one",
		MfrStr:     "Yubico",
		ProductStr: "Security Key",
		SerialNbr:  "12345678",
		VendorID:   0x1050,
		ProductID:  0x0407,
	}})

	if len(descriptors) != 1 {
		t.Fatalf("descriptors = %d, want 1", len(descriptors))
	}

	got := descriptors[0]
	if got.Transport != ModeWindowsProxy ||
		got.Path != "proxy://one" ||
		got.Manufacturer != "Yubico" ||
		got.Product != "Security Key" ||
		got.Serial != "12345678" ||
		got.VendorID != 0x1050 ||
		got.ProductID != 0x0407 {
		t.Fatalf("descriptor = %#v", got)
	}
}

func TestDiscoverAvailableCombinesSuccessfulSources(t *testing.T) {
	first := Descriptor{Transport: ModeHID, Path: "hid://one"}
	second := Descriptor{Transport: ModeSmartCard, Path: "reader-one"}

	devices, err := discoverAvailable(
		context.Background(),
		func(context.Context) ([]Descriptor, error) {
			return []Descriptor{first}, nil
		},
		func(context.Context) ([]Descriptor, error) {
			return []Descriptor{second}, nil
		},
	)
	if err != nil {
		t.Fatalf("discover available: %v", err)
	}
	if len(devices) != 2 ||
		devices[0].Transport != first.Transport ||
		devices[0].Path != first.Path ||
		devices[1].Transport != second.Transport ||
		devices[1].Path != second.Path {
		t.Fatalf("devices = %#v", devices)
	}
}

func TestDiscoverAvailableKeepsSuccessfulEmptySnapshot(t *testing.T) {
	sourceErr := errors.New("PC/SC unavailable")
	devices, err := discoverAvailable(
		context.Background(),
		func(context.Context) ([]Descriptor, error) {
			return nil, nil
		},
		func(context.Context) ([]Descriptor, error) {
			return nil, sourceErr
		},
	)
	if err != nil {
		t.Fatalf("discover available: %v", err)
	}
	if devices != nil {
		t.Fatalf("devices = %#v, want nil", devices)
	}
}

func TestDiscoverAvailableFailsWhenEverySourceFails(t *testing.T) {
	firstErr := errors.New("HID unavailable")
	secondErr := errors.New("PC/SC unavailable")
	_, err := discoverAvailable(
		context.Background(),
		func(context.Context) ([]Descriptor, error) {
			return nil, firstErr
		},
		func(context.Context) ([]Descriptor, error) {
			return nil, secondErr
		},
	)
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("error = %v, want both source errors", err)
	}
}
