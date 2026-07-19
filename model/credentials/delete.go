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
