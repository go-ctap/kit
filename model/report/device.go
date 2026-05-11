package report

import "github.com/go-ctap/kit/transport"

type DeviceReport struct {
	DeviceID     string         `json:"deviceId"`
	OrdinalAlias string         `json:"ordinalAlias,omitempty"`
	StableID     bool           `json:"stableId"`
	Transport    transport.Mode `json:"transport"`
	Path         string         `json:"path"`
	Manufacturer string         `json:"manufacturer,omitempty"`
	Product      string         `json:"product,omitempty"`
	Serial       string         `json:"serial,omitempty"`
	VendorID     uint16         `json:"vendorId"`
	ProductID    uint16         `json:"productId"`
}
