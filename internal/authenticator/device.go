package authenticator

import (
	"iter"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/webauthn"
)

type Lifecycle interface {
	Close() error
}

type InfoProvider interface {
	GetInfo() protocol.AuthenticatorGetInfoResponse
}

type TokenProvider interface {
	InfoProvider
	GetPinUvAuthTokenUsingPIN(pin string, permission protocol.Permission, rpID string) ([]byte, error)
	GetPinUvAuthTokenUsingUV(permission protocol.Permission, rpID string) ([]byte, error)
}

type CredentialManager interface {
	InfoProvider
	GetCredsMetadata(pinUvAuthToken []byte) (protocol.AuthenticatorCredentialManagementResponse, error)
	EnumerateRPs(pinUvAuthToken []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error]
	EnumerateCredentials(pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error]
	DeleteCredential(pinUvAuthToken []byte, credentialID credential.PublicKeyCredentialDescriptor) error
	UpdateUserInformation(pinUvAuthToken []byte, credentialID credential.PublicKeyCredentialDescriptor, user credential.PublicKeyCredentialUserEntity) error
}

type WebAuthnManager interface {
	InfoProvider
	MakeCredential(
		pinUvAuthToken []byte,
		clientData []byte,
		rp credential.PublicKeyCredentialRpEntity,
		user credential.PublicKeyCredentialUserEntity,
		pubKeyCredParams []credential.PublicKeyCredentialParameters,
		excludeList []credential.PublicKeyCredentialDescriptor,
		extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
		options map[protocol.Option]bool,
		enterpriseAttestation uint,
		attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
	) (protocol.AuthenticatorMakeCredentialResponse, error)
	GetAssertion(
		pinUvAuthToken []byte,
		rpID string,
		clientData []byte,
		allowList []credential.PublicKeyCredentialDescriptor,
		extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
		options map[protocol.Option]bool,
	) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error]
}

type LargeBlobManager interface {
	InfoProvider
	GetLargeBlobs() ([]protocol.LargeBlob, error)
	SetLargeBlobs(pinUvAuthToken []byte, blobs []protocol.LargeBlob) error
}

type ConfigManager interface {
	GetPINRetries() (uint, *bool, error)
	GetUVRetries() (uint, error)
	SetPIN(pin string) error
	ChangePIN(currentPin, newPin string) error
	Reset() error
	ToggleAlwaysUV(pinUvAuthToken []byte) error
	SetMinPINLength(pinUvAuthToken []byte, newMinPINLength uint, minPinLengthRPIDs []string, forceChangePin bool, pinComplexityPolicy bool) error
}

type BioEnrollmentManager interface {
	GetBioModality() (protocol.AuthenticatorBioEnrollmentResponse, error)
	GetFingerprintSensorInfo() (protocol.AuthenticatorBioEnrollmentResponse, error)
	EnrollBegin(pinUvAuthToken []byte, timeoutMilliseconds uint) (protocol.AuthenticatorBioEnrollmentResponse, error)
	EnrollCaptureNextSample(pinUvAuthToken []byte, templateID []byte, timeoutMilliseconds uint) (protocol.AuthenticatorBioEnrollmentResponse, error)
	CancelCurrentEnrollment() error
	EnumerateEnrollments(pinUvAuthToken []byte) (protocol.AuthenticatorBioEnrollmentResponse, error)
	SetFriendlyName(pinUvAuthToken []byte, templateID []byte, name string) error
	RemoveEnrollment(pinUvAuthToken []byte, templateID []byte) error
}

type Device interface {
	Lifecycle
	InfoProvider
	TokenProvider
	CredentialManager
	WebAuthnManager
	LargeBlobManager
	ConfigManager
	BioEnrollmentManager
}
