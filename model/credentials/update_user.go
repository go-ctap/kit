package credentials

import (
	"encoding/hex"
	"strings"

	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

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

func BuildUpdateUserPreview(operation UpdateUserOperation) (UpdateUserPreview, error) {
	target := operation.Target

	if strings.TrimSpace(target.Record.CredentialIDHex) == "" {
		return UpdateUserPreview{}, failure.New(failure.CodeCredentialIDRequired, failure.WithPhase(failure.PhaseValidation))
	}

	if strings.TrimSpace(target.RP.ID) == "" {
		return UpdateUserPreview{}, failure.New(failure.CodeRelyingPartyIDRequired, failure.WithPhase(failure.PhaseValidation))
	}

	proposed, err := ResolveUpdatedUser(operation)
	if err != nil {
		return UpdateUserPreview{}, err
	}

	return UpdateUserPreview{
		CredentialIDHex: target.Record.CredentialIDHex,
		RPID:            target.RP.ID,
		RPName:          target.RP.Name,
		Current:         target.User,
		Proposed:        proposed,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityWarning,
				Code:     "credential.update_user.mutation",
				Message:  "Resident credential user updates change authenticator state and should be previewed before execution.",
			},
			{
				Severity: safety.SeverityInfo,
				Code:     "credential.update_user.scope",
				Message:  "Only WebAuthn user fields are updated; credential ID and relying party binding stay unchanged.",
			},
		},
	}, nil
}

func ResolveUpdatedUser(operation UpdateUserOperation) (UserIdentity, error) {
	if !operation.UserIDProvided && !operation.NameProvided && !operation.DisplayProvided {
		return UserIdentity{}, failure.New(failure.CodeCredentialChangesRequired, failure.WithPhase(failure.PhaseValidation))
	}

	target := operation.Target
	proposed := target.User

	if operation.UserIDProvided {
		trimmed := strings.TrimSpace(operation.UserIDHex)
		if trimmed == "" {
			proposed.UserIDHex = ""
		} else {
			decoded, err := hex.DecodeString(trimmed)
			if err != nil {
				return UserIdentity{}, failure.Wrap(failure.CodeUserIDHexInvalid, err, failure.WithPhase(failure.PhaseValidation))
			}

			proposed.UserIDHex = hex.EncodeToString(decoded)
		}
	}

	if operation.NameProvided {
		proposed.Name = strings.TrimSpace(operation.Name)
	}

	if operation.DisplayProvided {
		proposed.DisplayName = strings.TrimSpace(operation.DisplayName)
	}

	if proposed.UserIDHex == "" {
		proposed.UserIDHex = target.User.UserIDHex
	}

	if proposed == target.User {
		return UserIdentity{}, failure.New(failure.CodeCredentialChangesRequired, failure.WithPhase(failure.PhaseValidation))
	}

	return proposed, nil
}
