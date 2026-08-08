package report

import (
	"github.com/telesma-app/token2"
	"github.com/telesma-app/yubico"
)

// DeviceVendorMetadata is an extensible tagged union of metadata returned by
// vendor-owned packages. A provider sets only its own field.
type DeviceVendorMetadata struct {
	Yubico *yubico.DeviceInfo `json:"yubico,omitempty"`
	Token2 *token2.DeviceInfo `json:"token2,omitempty"`
}
