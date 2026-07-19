package model

import "github.com/go-ctap/kit/model/config"

type SetAlwaysUVOperation struct {
	Target config.AlwaysUVTarget `json:"target"`
	DryRun bool                  `json:"dryRun,omitempty"`
}

type SetMinPINLengthOperation struct {
	NewMinPINLength     *uint    `json:"newMinPINLength,omitempty"`
	MinPINLengthRPIDs   []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePIN      bool     `json:"forceChangePin,omitempty"`
	PINComplexityPolicy bool     `json:"pinComplexityPolicy,omitempty"`
	DryRun              bool     `json:"dryRun,omitempty"`
}

type EnableLongTouchForResetOperation struct {
	DryRun bool `json:"dryRun,omitempty"`
}
