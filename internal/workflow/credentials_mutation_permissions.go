package workflow

import (
	"encoding/hex"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) inventoryMutationPermissions(
	required protocol.Permission,
) (protocol.Permission, protocol.Permission, error) {
	inventory, err := inventoryPermission(r.infoProvider().GetInfo())
	if err != nil {
		return protocol.PermissionNone, protocol.PermissionNone, err
	}
	if required&protocol.PermissionCredentialManagement != 0 {
		return required, required, nil
	}

	if inventory == protocol.PermissionPersistentCredentialManagementReadOnly {
		return inventory, required, nil
	}

	grant := required | protocol.PermissionCredentialManagement

	return grant, grant, nil
}

func (r Runner) credentialMutationRPID(
	target appcredentials.CredentialTarget,
) string {
	if !r.env.StrictPermissions {
		return ""
	}

	return target.RP.ID
}

func credentialDescriptor(record appcredentials.CredentialRecord) (credential.PublicKeyCredentialDescriptor, error) {
	id, err := hex.DecodeString(record.CredentialIDHex)
	if err != nil {
		return credential.PublicKeyCredentialDescriptor{}, failure.Wrap(
			failure.CodeInternalError,
			err,
			failure.WithPhase(failure.PhaseDecode),
		)
	}

	return credential.PublicKeyCredentialDescriptor{
		Type:       credential.PublicKeyCredentialType(record.CredentialType),
		ID:         id,
		Transports: credentialAuthenticatorTransports(record.CredentialTransports),
	}, nil
}

func credentialAuthenticatorTransports(transports []string) []credential.AuthenticatorTransport {
	if len(transports) == 0 {
		return nil
	}

	out := make([]credential.AuthenticatorTransport, 0, len(transports))
	for _, transport := range transports {
		out = append(out, credential.AuthenticatorTransport(transport))
	}

	return out
}
