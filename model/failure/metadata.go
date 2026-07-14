package failure

import (
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

func canonicalOperation(operation string) string {
	switch operation {
	case "inspect",
		"credentials.list",
		"credentials.delete",
		"credentials.updateUser",
		"largeBlobs.read",
		"largeBlobs.list",
		"largeBlobs.write",
		"largeBlobs.delete",
		"largeBlobs.garbageCollect",
		"config.status",
		"config.bio.sensorInfo",
		"config.bio.list",
		"config.bio.enroll",
		"config.bio.rename",
		"config.bio.remove",
		"config.reset.factory",
		"config.pin.set",
		"config.pin.change",
		"config.alwaysUv.set",
		"config.minPinLength.set",
		"webauthn.makeCredential",
		"webauthn.getAssertion":
		return operation
	default:
		return ""
	}
}

func canonicalCTAP(detail *CTAPDetail) *CTAPDetail {
	if detail == nil {
		return nil
	}

	canonical := cloneCTAP(detail)
	command := protocol.Command(canonical.CommandCode)
	canonical.Command, _ = command.Name()
	canonical.Status, _ = ctaptransport.StatusCode(canonical.StatusCode).Name()
	canonical.SubCommandFamily = ""
	canonical.SubCommand = ""
	if canonical.SubCommandCode == nil {
		return canonical
	}

	canonical.SubCommandFamily, canonical.SubCommand = canonicalSubCommand(
		command,
		*canonical.SubCommandCode,
	)

	return canonical
}

func canonicalSubCommand(command protocol.Command, value uint64) (string, string) {
	var family, name string
	switch command {
	case protocol.AuthenticatorClientPIN:
		family = "clientPIN"
		name, _ = protocol.ClientPINSubCommand(value).Name()
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		family = "bioEnrollment"
		name, _ = protocol.BioEnrollmentSubCommand(value).Name()
	case protocol.AuthenticatorCredentialManagement, protocol.PrototypeAuthenticatorCredentialManagement:
		family = "credentialManagement"
		name, _ = protocol.CredentialManagementSubCommand(value).Name()
	case protocol.AuthenticatorConfig:
		family = "config"
		name, _ = protocol.ConfigSubCommand(value).Name()
	}

	return family, name
}
