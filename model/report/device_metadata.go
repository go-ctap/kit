package report

import (
	"github.com/go-ctap/token2"
	"github.com/go-ctap/yubico"
)

// DeviceVendorMetadata is an extensible tagged union of metadata returned by
// vendor-owned packages. A provider sets only its own field.
type DeviceVendorMetadata struct {
	Yubico *yubico.DeviceInfo `json:"yubico,omitempty"`
	Token2 *token2.DeviceInfo `json:"token2,omitempty"`
}
