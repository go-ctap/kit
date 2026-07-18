package transport

import (
	"testing"

	"github.com/go-ctap/ctap/options"
)

func TestDiscoveryOptionsFollowResolvedMode(t *testing.T) {
	if options.NewOptions(discoveryOptions(ModeHID)...).UseNamedPipe {
		t.Fatal("HID discovery enabled named pipes")
	}

	if !options.NewOptions(discoveryOptions(ModeWindowsProxy)...).UseNamedPipe {
		t.Fatal("Windows proxy discovery did not enable named pipes")
	}
}
