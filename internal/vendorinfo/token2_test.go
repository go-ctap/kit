package vendorinfo

import (
	"context"
	"slices"
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/token2"
)

func TestToken2PCSCCandidatePropagatesContext(t *testing.T) {
	type contextKey struct{}

	marker := new(int)
	ctx := context.WithValue(context.Background(), contextKey{}, marker)
	device := &recordingToken2PCSCDevice{
		serial: "72103654095303",
	}

	candidate, ok := token2PCSCCandidate(ctx, device)
	if !ok || candidate.metadata.Serial != device.serial {
		t.Fatalf("candidate = %#v, ok = %v", candidate, ok)
	}
	for name, recorded := range map[string]context.Context{
		"SerialNumber": device.serialCtx,
		"Config":       device.configCtx,
	} {
		if got := recorded.Value(contextKey{}); got != marker {
			t.Fatalf("%s context value = %v, want marker", name, got)
		}
	}
}

type recordingToken2PCSCDevice struct {
	serial    string
	serialCtx context.Context
	configCtx context.Context
}

func (d *recordingToken2PCSCDevice) Close() error { return nil }

func (d *recordingToken2PCSCDevice) SerialNumber(ctx context.Context) (string, error) {
	d.serialCtx = ctx

	return d.serial, nil
}

func (d *recordingToken2PCSCDevice) Config(ctx context.Context) (token2.Config, error) {
	d.configCtx = ctx

	return token2.Config{}, nil
}

func TestToken2IdentityMetadata(t *testing.T) {
	tests := []struct {
		name         string
		serialNumber string
		model        string
		revision     string
	}{
		{
			name:         "branded",
			serialNumber: "72103654095303",
			model:        "Token2 Bio3 Dual A+C PIN+ R3.2",
			revision:     "R3.2",
		},
		{
			name:         "unbranded",
			serialNumber: "22103654095303",
			model:        "Bio3 Dual A+C PIN+ R3.2",
			revision:     "R3.2",
		},
		{
			name:         "distinct unbranded octo branding",
			serialNumber: "66113654095303",
			model:        "Unbranded Octo Dual NFC PIN+ PIV+ R3.3",
			revision:     "R3.3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := token2IdentityMetadata(test.serialNumber)
			if metadata.Serial != test.serialNumber || metadata.Model != test.model || metadata.Firmware != test.revision {
				t.Fatalf("metadata = %#v", metadata)
			}
		})
	}
}

func TestSelectToken2Candidate(t *testing.T) {
	candidates := []token2Candidate{
		{metadata: report.DeviceMetadata{Serial: "72103654095303", Model: "first"}},
		{metadata: report.DeviceMetadata{Serial: "66104666000042", Model: "second"}},
	}

	metadata, ok := selectToken2Candidate(candidates, "66104666000042", "")
	if !ok || metadata.Model != "second" {
		t.Fatalf("exact selection = %#v, ok = %v", metadata, ok)
	}
	metadata, ok = selectToken2Candidate(candidates, "", "54095303")
	if !ok || metadata.Model != "first" {
		t.Fatalf("suffix selection = %#v, ok = %v", metadata, ok)
	}
	if _, ok := selectToken2Candidate(candidates, "", ""); ok {
		t.Fatal("ambiguous candidates were selected")
	}
	if _, ok := selectToken2Candidate(candidates[:1], "different", ""); ok {
		t.Fatal("candidate with a different reported serial was selected")
	}
}

func TestAddToken2ConfigNormalizesReportedCapabilities(t *testing.T) {
	config, err := token2.ParseConfig([]byte{
		0x00,
		0x14,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x01, 0x00,
		0x13,
	})
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	var metadata report.DeviceMetadata
	addToken2Config(&metadata, config)
	if len(metadata.Interfaces) != 2 {
		t.Fatalf("interfaces = %#v", metadata.Interfaces)
	}
	usb := metadata.Interfaces[0]
	want := []report.Capability{report.CapabilityOTP, report.CapabilityCCID, report.CapabilityCTAP2}
	if usb.Interface != report.InterfaceUSB || !slices.Equal(usb.Supported, want) {
		t.Fatalf("USB interface = %#v", usb)
	}
	if metadata.Interfaces[1].Interface != report.InterfaceNFC {
		t.Fatalf("NFC interface = %#v", metadata.Interfaces[1])
	}
}
