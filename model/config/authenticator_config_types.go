package config

import (
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

type AuthenticatorConfigOperation string

const (
	AuthenticatorConfigAlwaysUV     AuthenticatorConfigOperation = "alwaysUv"
	AuthenticatorConfigMinPINLength AuthenticatorConfigOperation = "setMinPINLength"
)

type AlwaysUVTarget string

const (
	AlwaysUVTargetEnable  AlwaysUVTarget = "enable"
	AlwaysUVTargetDisable AlwaysUVTarget = "disable"
)

type MinPINLengthRequest struct {
	Length              uint     `json:"newMinPINLength"`
	RPIDs               []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePin      bool     `json:"forceChangePin"`
	PinComplexityPolicy bool     `json:"pinComplexityPolicy"`
	Confirmed           bool     `json:"-"`
}

type AuthenticatorConfigPreview struct {
	Operation             AuthenticatorConfigOperation `json:"operation"`
	Device                report.DeviceReport          `json:"device"`
	Authenticator         AuthenticatorConfigStatus    `json:"authenticatorConfig"`
	Target                AlwaysUVTarget               `json:"target,omitempty"`
	CurrentAlwaysUV       *bool                        `json:"currentAlwaysUv,omitempty"`
	RequestedAlwaysUV     bool                         `json:"requestedAlwaysUv,omitempty"`
	CurrentMinPINLength   *uint                        `json:"currentMinPINLength,omitempty"`
	RequestedMinPINLength *uint                        `json:"requestedMinPINLength,omitempty"`
	MaxPINLength          *uint                        `json:"maxPINLength,omitempty"`
	RPIDs                 []string                     `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePin        bool                         `json:"forceChangePin,omitempty"`
	PinComplexityPolicy   bool                         `json:"pinComplexityPolicy,omitempty"`
	Mode                  safety.PreviewMode           `json:"mode"`
	Warnings              []safety.Warning             `json:"warnings,omitempty"`
}

type AuthenticatorConfigResult struct {
	Operation       AuthenticatorConfigOperation `json:"operation"`
	DeviceID        string                       `json:"deviceId"`
	Target          AlwaysUVTarget               `json:"target,omitempty"`
	NewMinPINLength uint                         `json:"newMinPINLength,omitempty"`
	State           StateValue                   `json:"state"`
}

type AuthenticatorConfigStatus struct {
	State           StateValue      `json:"state"`
	Supported       bool            `json:"supported"`
	Configured      *bool           `json:"configured,omitempty"`
	PreviewOnly     bool            `json:"previewOnly,omitempty"`
	UVAcfg          CapabilityState `json:"uvAcfg"`
	AlwaysUV        CapabilityState `json:"alwaysUv"`
	SetMinPINLength CapabilityState `json:"setMinPINLength"`
}
