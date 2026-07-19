package credentials

import "github.com/go-ctap/kit/model/safety"

type UpdateUserPreview struct {
	CredentialIDHex string           `json:"credentialIDHex"`
	RPID            string           `json:"rpID"`
	RPName          string           `json:"rpName,omitempty"`
	Current         UserIdentity     `json:"current"`
	Proposed        UserIdentity     `json:"proposed"`
	Warnings        []safety.Warning `json:"warnings,omitempty"`
}

type UpdateUserResult struct {
	DeviceFingerprint string       `json:"deviceFingerprint"`
	CredentialIDHex   string       `json:"credentialIDHex"`
	RPID              string       `json:"rpID"`
	RPName            string       `json:"rpName,omitempty"`
	Previous          UserIdentity `json:"previous"`
	Current           UserIdentity `json:"current"`
}
