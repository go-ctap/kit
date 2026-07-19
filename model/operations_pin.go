package model

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
