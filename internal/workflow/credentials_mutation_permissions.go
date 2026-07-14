package workflow

import (
	"encoding/hex"

	"github.com/go-ctap/ctap/credential"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) credentialMutationRPID(target appcredentials.CredentialTarget) string {
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
