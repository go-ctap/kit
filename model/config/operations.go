package config

type SetPINOperation struct {
	// NewPIN is omitted during JSON encoding so callers cannot accidentally log
	// or persist it with the operation DTO.
	NewPIN string `json:"-"`
	DryRun bool   `json:"dryRun,omitempty"`
}

type ChangePINOperation struct {
	// CurrentPIN and NewPIN are omitted during JSON encoding so callers cannot
	// accidentally log or persist them.
	CurrentPIN string `json:"-"`
	NewPIN     string `json:"-"`
	DryRun     bool   `json:"dryRun,omitempty"`
}

type SetAlwaysUVOperation struct {
	Target AlwaysUVTarget `json:"target"`
	DryRun bool           `json:"dryRun,omitempty"`
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

type BioEnrollOperation struct {
	TimeoutMilliseconds uint `json:"timeoutMilliseconds,omitempty"`
	DryRun              bool `json:"dryRun,omitempty"`
}

type BioRenameOperation struct {
	TemplateIDHex string `json:"templateIDHex"`
	FriendlyName  string `json:"friendlyName"`
	DryRun        bool   `json:"dryRun,omitempty"`
}

type BioRemoveOperation struct {
	TemplateIDHex string `json:"templateIDHex"`
	DryRun        bool   `json:"dryRun,omitempty"`
}

type ResetFactoryOperation struct {
	DryRun bool `json:"dryRun,omitempty"`
}
