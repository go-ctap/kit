package ctapkit

import (
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

func TestProbeDeviceMetadataRejectsInvalidHandle(t *testing.T) {
	metadata, err := ProbeDeviceMetadata(t.Context(), Device{})
	if metadata != nil {
		t.Fatalf("metadata = %#v, want nil", metadata)
	}

	if !failure.IsCode(err, failure.CodeDeviceHandleInvalid) {
		t.Fatalf("error = %v, want %s", err, failure.CodeDeviceHandleInvalid)
	}

	if got := failure.Snapshot(err).Phase; got != failure.PhaseMetadata {
		t.Fatalf("phase = %q, want %q", got, failure.PhaseMetadata)
	}
}
