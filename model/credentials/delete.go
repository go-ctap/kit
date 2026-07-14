package credentials

import "github.com/go-ctap/kit/model/safety"

type DeletePreview struct {
	CredentialIDHex string           `json:"credentialIDHex"`
	RPID            string           `json:"rpID"`
	RPName          string           `json:"rpName,omitempty"`
	UserIDHex       string           `json:"userIDHex,omitempty"`
	UserName        string           `json:"userName,omitempty"`
	DisplayName     string           `json:"displayName,omitempty"`
	Warnings        []safety.Warning `json:"warnings,omitempty"`
}

type DeleteResult struct {
	DeviceFingerprint string `json:"deviceFingerprint"`
	CredentialIDHex   string `json:"credentialIDHex"`
	RPID              string `json:"rpID"`
	RPName            string `json:"rpName,omitempty"`
	UserIDHex         string `json:"userIDHex,omitempty"`
	UserName          string `json:"userName,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
}

func BuildDeletePreview(report InventoryReport, credentialIDHex string) (DeletePreview, error) {
	target, err := FindCredentialByHexID(report, credentialIDHex)
	if err != nil {
		return DeletePreview{}, err
	}

	return DeletePreview{
		CredentialIDHex: target.Record.CredentialIDHex,
		RPID:            target.RP.ID,
		RPName:          target.RP.Name,
		UserIDHex:       target.User.UserIDHex,
		UserName:        target.User.Name,
		DisplayName:     target.User.DisplayName,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityDestructive,
				Code:     "credential.delete.destructive",
				Message:  "Resident credential deletion is destructive and cannot be undone.",
			},
			{
				Severity: safety.SeverityWarning,
				Code:     "credential.delete.irreversible",
				Message:  "The relying party may stop working until the credential is recreated.",
			},
		},
	}, nil
}
