package ctapkit

import (
	"context"

	"github.com/go-ctap/kit/internal/vendorinfo"
	"github.com/go-ctap/kit/model/report"
)

// CanProbeDeviceMetadata reports whether the runtime has a metadata probe for
// the discovered device.
func CanProbeDeviceMetadata(device report.DeviceReport) bool {
	return vendorinfo.CanProbe(device)
}

// ProbeDeviceMetadata obtains optional vendor metadata without opening a
// public Authenticator handle.
func ProbeDeviceMetadata(ctx context.Context, device report.DeviceReport) (*report.DeviceMetadata, error) {
	return vendorinfo.Probe(ctx, device)
}
