//go:build windows

package transport

import (
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

func TestResolveWindowsMode(t *testing.T) {
	tests := []struct {
		name      string
		requested Mode
		elevated  bool
		want      Mode
		wantErr   bool
	}{
		{name: "auto elevated", requested: ModeAuto, elevated: true, want: ModeHID},
		{name: "auto unelevated", requested: ModeAuto, want: ModeWindowsProxy},
		{name: "explicit HID", requested: ModeHID, want: ModeHID},
		{name: "explicit proxy", requested: ModeWindowsProxy, want: ModeWindowsProxy},
		{name: "unsupported", requested: "nfc", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveWindowsMode(test.requested, test.elevated)
			if test.wantErr {
				if !failure.IsCode(err, failure.CodeTransportModeUnsupported) {
					t.Fatalf("resolve error = %v, want %s", err, failure.CodeTransportModeUnsupported)
				}

				return
			}

			if err != nil {
				t.Fatalf("resolve mode: %v", err)
			}

			if got != test.want {
				t.Fatalf("resolved mode = %q, want %q", got, test.want)
			}
		})
	}
}
