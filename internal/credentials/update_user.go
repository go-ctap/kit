package credentials

import (
	"encoding/hex"
	"strings"

	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

func BuildUpdateUserPreview(operation appcredentials.UpdateUserOperation) (appcredentials.UpdateUserPreview, error) {
	target := operation.Target

	if strings.TrimSpace(target.Record.CredentialIDHex) == "" {
		return appcredentials.UpdateUserPreview{}, failure.New(
			failure.CodeCredentialIDRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	if strings.TrimSpace(target.RP.ID) == "" {
		return appcredentials.UpdateUserPreview{}, failure.New(
			failure.CodeRelyingPartyIDRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	proposed, err := ResolveUpdatedUser(operation)
	if err != nil {
		return appcredentials.UpdateUserPreview{}, err
	}

	return appcredentials.UpdateUserPreview{
		CredentialIDHex: target.Record.CredentialIDHex,
		RPID:            target.RP.ID,
		RPName:          target.RP.Name,
		Current:         target.User,
		Proposed:        proposed,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityWarning,
				Code:     "credential.update_user.mutation",
				Message:  "Only the stored user name and display name are changed for this discoverable credential.",
			},
			{
				Severity: safety.SeverityInfo,
				Code:     "credential.update_user.scope",
				Message:  "CTAP requires user.id to remain identical and leaves the credential ID, key pair, and relying-party binding unchanged.",
			},
		},
	}, nil
}

func ResolveUpdatedUser(operation appcredentials.UpdateUserOperation) (appcredentials.UserIdentity, error) {
	if !operation.UserIDProvided && !operation.NameProvided && !operation.DisplayProvided {
		return appcredentials.UserIdentity{}, failure.New(
			failure.CodeCredentialChangesRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	target := operation.Target
	proposed := target.User

	if operation.UserIDProvided {
		trimmed := strings.TrimSpace(operation.UserIDHex)
		decoded, err := hex.DecodeString(trimmed)
		if err != nil {
			return appcredentials.UserIdentity{}, failure.Wrap(
				failure.CodeUserIDHexInvalid,
				err,
				failure.WithPhase(failure.PhaseValidation),
			)
		}

		if hex.EncodeToString(decoded) != strings.ToLower(target.User.UserIDHex) {
			return appcredentials.UserIdentity{}, failure.New(
				failure.CodeCTAPParameterInvalid,
				failure.WithPhase(failure.PhaseValidation),
			)
		}
	}

	if operation.NameProvided {
		proposed.Name = strings.TrimSpace(operation.Name)
	}

	if operation.DisplayProvided {
		proposed.DisplayName = strings.TrimSpace(operation.DisplayName)
	}

	if proposed == target.User {
		return appcredentials.UserIdentity{}, failure.New(
			failure.CodeCredentialChangesRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return proposed, nil
}
