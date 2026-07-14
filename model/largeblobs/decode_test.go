package largeblobs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/kit/model/failure"
)

func TestDecodeLargeBlob(t *testing.T) {
	cborPayload, err := cbor.Marshal(map[string]any{"ok": true, "count": uint64(2)})
	if err != nil {
		t.Fatalf("Marshal(cbor): %v", err)
	}

	tests := []struct {
		name        string
		raw         []byte
		present     bool
		mode        DecodeMode
		wantRequest bool
		wantSuccess bool
		wantFailure failure.Code
	}{
		{name: "raw default", raw: []byte("opaque"), present: true, mode: DecodeModeNone},
		{name: "utf8", raw: []byte("hello"), present: true, mode: DecodeModeUTF8, wantRequest: true, wantSuccess: true},
		{name: "json", raw: []byte(`{"ok":true}`), present: true, mode: DecodeModeJSON, wantRequest: true, wantSuccess: true},
		{name: "cbor", raw: cborPayload, present: true, mode: DecodeModeCBOR, wantRequest: true, wantSuccess: true},
		{name: "malformed utf8", raw: []byte{0xff}, present: true, mode: DecodeModeUTF8, wantRequest: true, wantFailure: failure.CodeLargeBlobUTF8Invalid},
		{name: "malformed json", raw: []byte(`{"ok"`), present: true, mode: DecodeModeJSON, wantRequest: true, wantFailure: failure.CodeLargeBlobJSONInvalid},
		{name: "malformed cbor", raw: []byte{0xff}, present: true, mode: DecodeModeCBOR, wantRequest: true, wantFailure: failure.CodeLargeBlobCBORInvalid},
		{name: "unsupported", raw: []byte("opaque"), present: true, mode: DecodeMode("future"), wantRequest: true, wantFailure: failure.CodeLargeBlobDecodeModeUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := DecodeLargeBlob(tt.raw, tt.present, tt.mode)
			if status.Requested != tt.wantRequest {
				t.Fatalf("Requested = %v, want %v", status.Requested, tt.wantRequest)
			}

			if status.Success != tt.wantSuccess {
				t.Fatalf("Success = %v, want %v (failure %#v)", status.Success, tt.wantSuccess, status.Failure)
			}

			if tt.wantFailure == "" {
				if status.Failure != nil {
					t.Fatalf("Failure = %#v, want nil", status.Failure)
				}
			} else if status.Failure == nil || status.Failure.Code != tt.wantFailure {
				t.Fatalf("Failure = %#v, want code %s", status.Failure, tt.wantFailure)
			} else if status.Failure.Phase != failure.PhaseDecode {
				t.Fatalf("Failure phase = %q, want %q", status.Failure.Phase, failure.PhaseDecode)
			}
			if tt.wantRequest && status.Label == "" {
				t.Fatal("Label empty for requested decode")
			}
		})
	}
}

func TestDecodeMissingBlobIsState(t *testing.T) {
	status := DecodeLargeBlob(nil, false, DecodeModeJSON)
	if !status.Requested {
		t.Fatal("Requested = false, want true")
	}

	if status.Success {
		t.Fatal("Success = true, want false")
	}

	if status.Failure == nil || status.Failure.Code != failure.CodeLargeBlobMissing {
		t.Fatalf("Failure = %#v, want code %s", status.Failure, failure.CodeLargeBlobMissing)
	}
}

func TestSupportReportPreservesExplicitZeroLargeBlobArrayLimit(t *testing.T) {
	report := SupportReport{
		LargeBlobs:                  true,
		LargeBlobKeyExtension:       true,
		MaxSerializedLargeBlobArray: ptr(uint(0)),
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !strings.Contains(string(raw), `"maxSerializedLargeBlobArray":0`) {
		t.Fatalf("JSON missing explicit zero large blob limit: %s", raw)
	}
}

func TestSupportReportOmitsAbsentLargeBlobArrayLimit(t *testing.T) {
	raw, err := json.Marshal(SupportReport{LargeBlobs: true})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if strings.Contains(string(raw), "maxSerializedLargeBlobArray") {
		t.Fatalf("JSON included absent large blob limit: %s", raw)
	}
}

func ptr[T any](value T) *T {
	return &value
}
