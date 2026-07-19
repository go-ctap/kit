package credentials

import (
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/safety"
)

func BuildDeletePreview(
	report appcredentials.InventoryReport,
	credentialIDHex string,
) (appcredentials.DeletePreview, error) {
	target, err := FindByHexID(report, credentialIDHex)
	if err != nil {
		return appcredentials.DeletePreview{}, err
	}

	return appcredentials.DeletePreview{
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
				Message:  "The selected discoverable credential is deleted and its credential ID will no longer resolve on this authenticator; this cannot be undone.",
			},
			{
				Severity: safety.SeverityWarning,
				Code:     "credential.delete.associated_large_blob",
				Message:  "CTAP does not require credential deletion to remove its associated large blob; delete that blob separately or leave it for later garbage collection.",
			},
		},
	}, nil
}
