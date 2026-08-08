package report

import "github.com/telesma-app/kit/transport"

// AttachmentID identifies one currently reachable transport endpoint. It is
// not a physical-device identity and is never derived from hardware identity.
type AttachmentID string

// USBReport contains observations reported by USB/HID topology. ReportedSerial
// is not the canonical hardware serial returned by a vendor provider.
type USBReport struct {
	Manufacturer   string `json:"manufacturer,omitempty"`
	Product        string `json:"product,omitempty"`
	ReportedSerial string `json:"reportedSerial,omitempty"`
	VendorID       uint16 `json:"vendorId"`
	ProductID      uint16 `json:"productId"`
}

// SmartCardReport describes a PC/SC attachment separately from card identity.
type SmartCardReport struct {
	Reader    string                       `json:"reader"`
	ATR       string                       `json:"atr,omitempty"`
	Interface transport.SmartCardInterface `json:"interface"`
}

// AttachmentReport is the transport-layer view of one reachable CTAP
// authenticator.
type AttachmentReport struct {
	ID        AttachmentID     `json:"id"`
	Transport transport.Mode   `json:"transport"`
	USB       *USBReport       `json:"usb,omitempty"`
	SmartCard *SmartCardReport `json:"smartCard,omitempty"`
}

type DeviceVendor string

const (
	DeviceVendorYubico DeviceVendor = "yubico"
	DeviceVendorToken2 DeviceVendor = "token2"
)

// DeviceIdentityReport is the stable identity summary derived from vendor
// metadata.
type DeviceIdentityReport struct {
	Vendor       DeviceVendor `json:"vendor"`
	Name         string       `json:"name,omitempty"`
	SerialNumber string       `json:"serialNumber,omitempty"`
}

// DeviceReport describes one selectable transport attachment and its resolved
// physical-device identity and vendor metadata.
type DeviceReport struct {
	Attachment     AttachmentReport      `json:"attachment"`
	Identity       *DeviceIdentityReport `json:"identity,omitempty"`
	VendorMetadata *DeviceVendorMetadata `json:"vendorMetadata,omitempty"`
}
