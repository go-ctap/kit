package workflow

import (
	"encoding/hex"

	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
)

func (r Runner) credentialMutationRPID(target appcredentials.CredentialTarget) string {
	if !r.env.StrictPermissions {
		return ""
	}

	return target.RP.ID
}

func credentialDescriptor(record appcredentials.CredentialRecord) (webauthntypes.PublicKeyCredentialDescriptor, error) {
	id, err := hex.DecodeString(record.CredentialIDHex)
	if err != nil {
		return webauthntypes.PublicKeyCredentialDescriptor{}, model.NewRuntimeError(
			model.ErrorInvalidState,
			"cached credential has invalid credential id",
			err,
		)
	}

	return webauthntypes.PublicKeyCredentialDescriptor{
		Type:       webauthntypes.PublicKeyCredentialType(record.CredentialType),
		ID:         id,
		Transports: credentialAuthenticatorTransports(record.CredentialTransports),
	}, nil
}

func credentialAuthenticatorTransports(transports []string) []webauthntypes.AuthenticatorTransport {
	if len(transports) == 0 {
		return nil
	}

	out := make([]webauthntypes.AuthenticatorTransport, 0, len(transports))
	for _, transport := range transports {
		out = append(out, webauthntypes.AuthenticatorTransport(transport))
	}

	return out
}
