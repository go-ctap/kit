package config

import (
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

type PINMutationOperation string

const (
	PINMutationSet    PINMutationOperation = "set"
	PINMutationChange PINMutationOperation = "change"
)

type PINStatus struct {
	State               StateValue `json:"state"`
	Supported           bool       `json:"supported"`
	Configured          *bool      `json:"configured,omitempty"`
	ProtocolSupported   bool       `json:"protocolSupported"`
	MinPINLength        *uint      `json:"minPINLength,omitempty"`
	MaxPINLength        *uint      `json:"maxPINLength,omitempty"`
	ForcePINChange      *bool      `json:"forcePINChange,omitempty"`
	PinComplexityPolicy *bool      `json:"pinComplexityPolicy,omitempty"`
	PinComplexityURL    []byte     `json:"pinComplexityPolicyURL,omitempty"`
	Retries             RetryState `json:"retries"`
}

type PINMutationPreview struct {
	Operation PINMutationOperation `json:"operation"`
	Device    report.DeviceReport  `json:"device"`
	PIN       PINStatus            `json:"pin"`
	Mode      safety.PreviewMode   `json:"mode"`
	Warnings  []safety.Warning     `json:"warnings,omitempty"`
}

type PINMutationResult struct {
	Operation PINMutationOperation `json:"operation"`
	DeviceID  string               `json:"deviceId"`
	PINState  StateValue           `json:"pinState"`
}
