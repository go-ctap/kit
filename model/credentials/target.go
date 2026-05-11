package credentials

import (
	"fmt"
	"strings"
)

type CredentialTarget struct {
	Record CredentialRecord
	RP     RelyingParty
	User   UserIdentity
}

type RelyingParty struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	IDHashHex string `json:"idHashHex,omitempty"`
}

type UserIdentity struct {
	UserIDHex   string `json:"userIDHex,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

func FindCredentialByHexID(report InventoryReport, credentialIDHex string) (CredentialTarget, error) {
	credentialIDHex = strings.TrimSpace(credentialIDHex)
	if credentialIDHex == "" {
		return CredentialTarget{}, fmt.Errorf("%w: credential id is required", ErrCredentialNotFound)
	}

	for _, group := range report.Groups {
		for _, record := range group.Credentials {
			if record.CredentialIDHex != credentialIDHex {
				continue
			}

			return CredentialTarget{
				Record: record,
				RP: RelyingParty{
					ID:        group.RPID,
					Name:      group.RPName,
					IDHashHex: group.RPIDHashHex,
				},
				User: UserIdentity{
					UserIDHex:   record.UserIDHex,
					Name:        record.UserName,
					DisplayName: record.DisplayName,
				},
			}, nil
		}
	}

	return CredentialTarget{}, fmt.Errorf("%w: %s", ErrCredentialNotFound, credentialIDHex)
}
