package config

import (
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

type AuthenticatorConfigOperation string

const (
	AuthenticatorConfigAlwaysUV     AuthenticatorConfigOperation = "alwaysUv"
	AuthenticatorConfigMinPINLength AuthenticatorConfigOperation = "setMinPINLength"
	AuthenticatorConfigLongTouch    AuthenticatorConfigOperation = "enableLongTouchForReset"
)

type AlwaysUVTarget string

const (
	AlwaysUVTargetEnable  AlwaysUVTarget = "enable"
	AlwaysUVTargetDisable AlwaysUVTarget = "disable"
)

type MinPINLengthRequest struct {
	NewMinPINLength     *uint    `json:"newMinPINLength,omitempty"`
	MinPINLengthRPIDs   []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePIN      bool     `json:"forceChangePin,omitempty"`
	PINComplexityPolicy bool     `json:"pinComplexityPolicy,omitempty"`
}

type AuthenticatorConfigPreview struct {
	Operation           AuthenticatorConfigOperation `json:"operation"`
	Device              report.DeviceReport          `json:"device"`
	Authenticator       AuthenticatorConfigStatus    `json:"authenticatorConfig"`
	Target              AlwaysUVTarget               `json:"target,omitempty"`
	CurrentAlwaysUV     *bool                        `json:"currentAlwaysUv,omitempty"`
	RequestedAlwaysUV   bool                         `json:"requestedAlwaysUv,omitempty"`
	CurrentMinPINLength uint                         `json:"currentMinPINLength"`
	NewMinPINLength     *uint                        `json:"newMinPINLength,omitempty"`
	MaxPINLength        uint                         `json:"maxPINLength"`
	MinPINLengthRPIDs   []string                     `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePIN      bool                         `json:"forceChangePin,omitempty"`
	PINComplexityPolicy bool                         `json:"pinComplexityPolicy,omitempty"`
	CurrentLongTouch    *bool                        `json:"currentLongTouchForReset,omitempty"`
	RequestedLongTouch  bool                         `json:"requestedLongTouchForReset,omitempty"`
	Mode                safety.PreviewMode           `json:"mode"`
	Warnings            []safety.Warning             `json:"warnings,omitempty"`
}

type AuthenticatorConfigResult struct {
	Operation           AuthenticatorConfigOperation `json:"operation"`
	DeviceFingerprint   string                       `json:"deviceFingerprint"`
	Target              AlwaysUVTarget               `json:"target,omitempty"`
	NewMinPINLength     *uint                        `json:"newMinPINLength,omitempty"`
	MinPINLengthRPIDs   []string                     `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePIN      bool                         `json:"forceChangePin,omitempty"`
	PINComplexityPolicy bool                         `json:"pinComplexityPolicy,omitempty"`
	State               StateValue                   `json:"state"`
}

type AuthenticatorConfigStatus struct {
	State             StateValue      `json:"state"`
	Supported         bool            `json:"supported"`
	Configured        *bool           `json:"configured,omitempty"`
	PreviewOnly       bool            `json:"previewOnly,omitempty"`
	UVAcfg            CapabilityState `json:"uvAcfg"`
	AlwaysUV          CapabilityState `json:"alwaysUv"`
	SetMinPINLength   CapabilityState `json:"setMinPINLength"`
	LongTouchForReset CapabilityState `json:"longTouchForReset"`
}
