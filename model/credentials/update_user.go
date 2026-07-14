package credentials

import (
	"encoding/hex"
	"strings"

	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/safety"
)

type UpdateUserRequest struct {
	CredentialIDHex string `json:"credentialIDHex"`
	UserIDHex       string `json:"userIDHex,omitempty"`
	Name            string `json:"name,omitempty"`
	DisplayName     string `json:"displayName,omitempty"`
	UserIDProvided  bool   `json:"-"`
	NameProvided    bool   `json:"-"`
	DisplayProvided bool   `json:"-"`
	Confirmed       bool   `json:"-"`
}

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

func BuildUpdateUserPreview(report InventoryReport, req UpdateUserRequest) (UpdateUserPreview, error) {
	if report.Support.PreviewOnly {
		return UpdateUserPreview{}, failure.New(failure.CodeCredentialManagementUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	target, err := FindCredentialByHexID(report, req.CredentialIDHex)
	if err != nil {
		return UpdateUserPreview{}, err
	}

	proposed, err := ResolveUpdatedUser(target, req)
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

func ResolveUpdatedUser(target CredentialTarget, req UpdateUserRequest) (UserIdentity, error) {
	if !req.UserIDProvided && !req.NameProvided && !req.DisplayProvided {
		return UserIdentity{}, failure.New(failure.CodeCredentialChangesRequired, failure.WithPhase(failure.PhaseValidation))
	}

	proposed := target.User

	if req.UserIDProvided {
		trimmed := strings.TrimSpace(req.UserIDHex)
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

	if req.NameProvided {
		proposed.Name = strings.TrimSpace(req.Name)
	}

	if req.DisplayProvided {
		proposed.DisplayName = strings.TrimSpace(req.DisplayName)
	}

	if proposed.UserIDHex == "" {
		proposed.UserIDHex = target.User.UserIDHex
	}

	if proposed == target.User {
		return UserIdentity{}, failure.New(failure.CodeCredentialChangesRequired, failure.WithPhase(failure.PhaseValidation))
	}

	return proposed, nil
}
