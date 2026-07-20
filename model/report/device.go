package report

import "github.com/go-ctap/kit/transport"

// Vendor identifies the authenticator manufacturer selected for optional
// vendor-specific runtime behavior.
type Vendor string

const (
	VendorUnknown Vendor = "unknown"
	VendorYubico  Vendor = "yubico"
	VendorToken2  Vendor = "token2"
)

// Capability identifies a normalized application exposed by an authenticator.
type Capability string

const (
	CapabilityOTP     Capability = "otp"
	CapabilityU2F     Capability = "u2f"
	CapabilityCCID    Capability = "ccid"
	CapabilityOpenPGP Capability = "openpgp"
	CapabilityPIV     Capability = "piv"
	CapabilityOATH    Capability = "oath"
	CapabilityCTAP2   Capability = "ctap2"
)

// Interface identifies a physical interface reported by vendor metadata.
type Interface string

const (
	InterfaceUSB Interface = "usb"
	InterfaceNFC Interface = "nfc"
)

// InterfaceReport describes supported and enabled applications on one interface.
type InterfaceReport struct {
	Interface Interface    `json:"interface"`
	Supported []Capability `json:"supported"`
	Enabled   []Capability `json:"enabled"`
}

// DeviceMetadata contains normalized details obtained from vendor protocols.
type DeviceMetadata struct {
	Model      string            `json:"model,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	Firmware   string            `json:"firmware,omitempty"`
	Interfaces []InterfaceReport `json:"interfaces,omitempty"`
}

// DeviceReport describes a discovered authenticator. Fingerprint follows a
// serial-backed device across attachments and otherwise identifies the current
// transport attachment.
type DeviceReport struct {
	Fingerprint  string          `json:"fingerprint"`
	OrdinalAlias string          `json:"ordinalAlias,omitempty"`
	Transport    transport.Mode  `json:"transport"`
	Path         string          `json:"path"`
	Manufacturer string          `json:"manufacturer,omitempty"`
	Product      string          `json:"product,omitempty"`
	Serial       string          `json:"serial,omitempty"`
	VendorID     uint16          `json:"vendorId"`
	ProductID    uint16          `json:"productId"`
	Vendor       Vendor          `json:"vendor"`
	Metadata     *DeviceMetadata `json:"metadata,omitempty"`
}
