package report

import (
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
)

// AttachmentID identifies one currently reachable transport endpoint. It is
// not a physical-device identity and is never derived from hardware identity.
type AttachmentID string

// Vendor identifies the provider of an optional hardware identity.
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

// Interface identifies a physical interface reported by a vendor.
type Interface string

const (
	InterfaceUSB Interface = "usb"
	InterfaceNFC Interface = "nfc"
)

// InterfaceReport describes supported and enabled applications on one
// physical interface.
type InterfaceReport struct {
	Interface Interface    `json:"interface"`
	Supported []Capability `json:"supported,omitempty"`
	Enabled   []Capability `json:"enabled,omitempty"`
}

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
	Reader string `json:"reader"`
	ATR    string `json:"atr,omitempty"`
}

// AttachmentReport is the transport-layer view of one reachable CTAP
// authenticator.
type AttachmentReport struct {
	ID        AttachmentID     `json:"id"`
	Transport transport.Mode   `json:"transport"`
	USB       *USBReport       `json:"usb,omitempty"`
	SmartCard *SmartCardReport `json:"smartCard,omitempty"`
}

// DeviceIdentity is an atomic hardware identity returned by one vendor
// provider.
type DeviceIdentity struct {
	Vendor     Vendor            `json:"vendor"`
	Model      string            `json:"model,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	Firmware   string            `json:"firmware,omitempty"`
	Interfaces []InterfaceReport `json:"interfaces,omitempty"`
}

// IdentityResolutionState describes optional identity progress.
type IdentityResolutionState string

const (
	IdentityResolving   IdentityResolutionState = "resolving"
	IdentityResolved    IdentityResolutionState = "resolved"
	IdentityUnavailable IdentityResolutionState = "unavailable"
	IdentityFailed      IdentityResolutionState = "failed"
)

// IdentityResolution exposes identity progress without turning it into a
// discovery or authenticator failure.
type IdentityResolution struct {
	State    IdentityResolutionState `json:"state"`
	Provider Vendor                  `json:"provider,omitempty"`
	Error    *failure.Failure        `json:"error,omitempty"`
}

// DeviceReport joins one selectable attachment with optional hardware
// identity.
type DeviceReport struct {
	Attachment AttachmentReport   `json:"attachment"`
	Identity   *DeviceIdentity    `json:"identity,omitempty"`
	Resolution IdentityResolution `json:"identityResolution"`
}
