package credentials

import (
	"strings"

	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func FindByHexID(report appcredentials.InventoryReport, credentialIDHex string) (appcredentials.CredentialTarget, error) {
	credentialIDHex = strings.TrimSpace(credentialIDHex)
	if credentialIDHex == "" {
		return appcredentials.CredentialTarget{}, failure.New(
			failure.CodeCredentialIDRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	for _, group := range report.Groups {
		for _, record := range group.Credentials {
			if record.CredentialIDHex != credentialIDHex {
				continue
			}

			return appcredentials.CredentialTarget{
				Record: record,
				RP: appcredentials.RelyingParty{
					ID:        group.RPID,
					Name:      group.RPName,
					IDHashHex: group.RPIDHashHex,
				},
				User: appcredentials.UserIdentity{
					UserIDHex:   record.UserIDHex,
					Name:        record.UserName,
					DisplayName: record.DisplayName,
				},
			}, nil
		}
	}

	return appcredentials.CredentialTarget{}, failure.New(
		failure.CodeCredentialNotFound,
		failure.WithPhase(failure.PhaseValidation),
	)
}
