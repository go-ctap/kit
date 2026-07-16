package workflow

import (
	"encoding/hex"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) mutationPermission(
	required protocol.Permission,
	prepareInventoryRefresh bool,
) (protocol.Permission, error) {
	if !prepareInventoryRefresh {
		return required, nil
	}

	if _, err := inventoryPermission(r.infoProvider().GetInfo()); err != nil {
		return protocol.PermissionNone, err
	}

	return required | protocol.PermissionCredentialManagement, nil
}

func inventoryGrantPermission(
	permission protocol.Permission,
	prepareInventoryRefresh bool,
) protocol.Permission {
	if !prepareInventoryRefresh {
		return protocol.PermissionNone
	}

	return permission
}

func (r Runner) credentialMutationRPID(
	target appcredentials.CredentialTarget,
	prepareInventoryRefresh bool,
) string {
	if prepareInventoryRefresh || !r.env.StrictPermissions {
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
