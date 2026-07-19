package model

type BioEnrollOperation struct {
	TimeoutMilliseconds uint `json:"timeoutMilliseconds,omitempty"`
	DryRun              bool `json:"dryRun,omitempty"`
}

type BioRenameOperation struct {
	TemplateIDHex string `json:"templateIdHex"`
	FriendlyName  string `json:"friendlyName"`
	DryRun        bool   `json:"dryRun,omitempty"`
}

type BioRemoveOperation struct {
	TemplateIDHex string `json:"templateIdHex"`
	DryRun        bool   `json:"dryRun,omitempty"`
}
