package report

import "github.com/go-ctap/kit/transport"

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

// DeviceReport describes one selectable transport attachment.
type DeviceReport struct {
	Attachment AttachmentReport `json:"attachment"`
}
