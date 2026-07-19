package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/vendorinfo"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
)

// CanProbeDeviceMetadata reports whether the runtime has a metadata probe for
// the discovered device.
func CanProbeDeviceMetadata(device report.DeviceReport) bool {
	return vendorinfo.CanProbe(device)
}

// ProbeDeviceMetadata obtains optional vendor metadata for a discovered device
// without opening a public Authenticator handle.
func ProbeDeviceMetadata(ctx context.Context, device Device) (*report.DeviceMetadata, error) {
	if !device.valid {
		return nil, failure.New(failure.CodeDeviceHandleInvalid,
			failure.WithPhase(failure.PhaseMetadata),
		)
	}

	return vendorinfo.Probe(ctx, device.report)
}
