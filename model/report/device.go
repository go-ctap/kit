package report

import "github.com/go-ctap/kit/transport"

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
	CapabilityHSMAuth Capability = "hsmauth"
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

// YubicoFormFactor identifies the physical YubiKey shape and connector.
type YubicoFormFactor string

const (
	YubicoFormFactorUnknown               YubicoFormFactor = "unknown"
	YubicoFormFactorUSBAKeychain          YubicoFormFactor = "usbAKeychain"
	YubicoFormFactorUSBANano              YubicoFormFactor = "usbANano"
	YubicoFormFactorUSBCKeychain          YubicoFormFactor = "usbCKeychain"
	YubicoFormFactorUSBCNano              YubicoFormFactor = "usbCNano"
	YubicoFormFactorUSBCLightning         YubicoFormFactor = "usbCLightning"
	YubicoFormFactorUSBABiometricKeychain YubicoFormFactor = "usbABiometricKeychain"
	YubicoFormFactorUSBCBiometricKeychain YubicoFormFactor = "usbCBiometricKeychain"
)

// YubicoReleaseType identifies the release stage of qualified firmware.
type YubicoReleaseType string

const (
	YubicoReleaseTypeAlpha YubicoReleaseType = "alpha"
	YubicoReleaseTypeBeta  YubicoReleaseType = "beta"
	YubicoReleaseTypeFinal YubicoReleaseType = "final"
)

// YubicoVersionQualifier describes the behavioral firmware version reported
// by development firmware.
type YubicoVersionQualifier struct {
	Version     string            `json:"version"`
	ReleaseType YubicoReleaseType `json:"releaseType"`
	Iteration   uint32            `json:"iteration"`
}

// YubicoDetails contains Yubico-specific identity and device state obtained
// from GET DEVICE INFORMATION. Raw unknown fields and undecoded flags remain
// private to the provider.
type YubicoDetails struct {
	PartNumber               string                  `json:"partNumber,omitempty"`
	FormFactor               YubicoFormFactor        `json:"formFactor"`
	IsFIPS                   bool                    `json:"isFIPS"`
	IsSecurityKey            bool                    `json:"isSecurityKey"`
	EffectiveFirmware        string                  `json:"effectiveFirmware,omitempty"`
	VersionQualifier         *YubicoVersionQualifier `json:"versionQualifier,omitempty"`
	AutoEjectTimeout         uint16                  `json:"autoEjectTimeout"`
	ChallengeResponseTimeout uint8                   `json:"challengeResponseTimeout"`
	Locked                   bool                    `json:"locked"`
	FIPSCapable              []Capability            `json:"fipsCapable,omitempty"`
	FIPSApproved             []Capability            `json:"fipsApproved,omitempty"`
	PINComplexity            bool                    `json:"pinComplexity"`
	NFCRestricted            bool                    `json:"nfcRestricted"`
	ResetBlocked             []Capability            `json:"resetBlocked,omitempty"`
	FPSVersion               string                  `json:"fpsVersion,omitempty"`
	STMVersion               string                  `json:"stmVersion,omitempty"`
}

// VendorDetails is an extensible tagged union of provider-specific details.
// A provider sets only its own field.
type VendorDetails struct {
	Yubico *YubicoDetails `json:"yubico,omitempty"`
}

// DeviceIdentity is an atomic hardware identity returned by one vendor
// provider.
type DeviceIdentity struct {
	Vendor     Vendor            `json:"vendor"`
	Model      string            `json:"model,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	Firmware   string            `json:"firmware,omitempty"`
	Interfaces []InterfaceReport `json:"interfaces,omitempty"`
	Details    *VendorDetails    `json:"details,omitempty"`
}

// IdentityResolutionState describes optional identity progress.
type IdentityResolutionState string

const (
	IdentityResolving   IdentityResolutionState = "resolving"
	IdentityResolved    IdentityResolutionState = "resolved"
	IdentityUnavailable IdentityResolutionState = "unavailable"
	IdentityFailed      IdentityResolutionState = "failed"
)

// IdentityResolution exposes identity progress. Failure details are emitted
// through Inventory events rather than retained in device snapshots.
type IdentityResolution struct {
	State    IdentityResolutionState `json:"state"`
	Provider Vendor                  `json:"provider,omitempty"`
}

// DeviceReport joins one selectable attachment with optional hardware
// identity.
type DeviceReport struct {
	Attachment AttachmentReport   `json:"attachment"`
	Identity   *DeviceIdentity    `json:"identity,omitempty"`
	Resolution IdentityResolution `json:"identityResolution"`
}
