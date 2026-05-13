package authenticator

import (
	"iter"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
)

type Lifecycle interface {
	Close() error
}

type InfoProvider interface {
	GetInfo() ctaptypes.AuthenticatorGetInfoResponse
}

type TokenProvider interface {
	InfoProvider
	GetPinUvAuthTokenUsingPIN(pin string, permission ctaptypes.Permission, rpID string) ([]byte, error)
	GetPinUvAuthTokenUsingUV(permission ctaptypes.Permission, rpID string) ([]byte, error)
}

type CredentialManager interface {
	InfoProvider
	GetCredsMetadata(pinUvAuthToken []byte) (ctaptypes.AuthenticatorCredentialManagementResponse, error)
	EnumerateRPs(pinUvAuthToken []byte) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error]
	EnumerateCredentials(pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error]
	DeleteCredential(pinUvAuthToken []byte, credentialID webauthntypes.PublicKeyCredentialDescriptor) error
	UpdateUserInformation(pinUvAuthToken []byte, credentialID webauthntypes.PublicKeyCredentialDescriptor, user webauthntypes.PublicKeyCredentialUserEntity) error
}

type WebAuthnManager interface {
	InfoProvider
	MakeCredential(
		pinUvAuthToken []byte,
		clientData []byte,
		rp webauthntypes.PublicKeyCredentialRpEntity,
		user webauthntypes.PublicKeyCredentialUserEntity,
		pubKeyCredParams []webauthntypes.PublicKeyCredentialParameters,
		excludeList []webauthntypes.PublicKeyCredentialDescriptor,
		extInputs *webauthntypes.CreateAuthenticationExtensionsClientInputs,
		options map[ctaptypes.Option]bool,
		enterpriseAttestation uint,
		attestationFormatsPreference []webauthntypes.AttestationStatementFormatIdentifier,
	) (ctaptypes.AuthenticatorMakeCredentialResponse, error)
	GetAssertion(
		pinUvAuthToken []byte,
		rpID string,
		clientData []byte,
		allowList []webauthntypes.PublicKeyCredentialDescriptor,
		extInputs *webauthntypes.GetAuthenticationExtensionsClientInputs,
		options map[ctaptypes.Option]bool,
	) iter.Seq2[ctaptypes.AuthenticatorGetAssertionResponse, error]
}

type LargeBlobManager interface {
	InfoProvider
	GetLargeBlobs() ([]ctaptypes.LargeBlob, error)
	SetLargeBlobs(pinUvAuthToken []byte, blobs []ctaptypes.LargeBlob) error
}

type ConfigManager interface {
	GetPINRetries() (uint, bool, error)
	GetUVRetries() (uint, error)
	SetPIN(pin string) error
	ChangePIN(currentPin, newPin string) error
	Reset() error
	ToggleAlwaysUV(pinUvAuthToken []byte) error
	SetMinPINLength(pinUvAuthToken []byte, newMinPINLength uint, minPinLengthRPIDs []string, forceChangePin bool, pinComplexityPolicy bool) error
}

type BioEnrollmentManager interface {
	GetBioModality() (ctaptypes.AuthenticatorBioEnrollmentResponse, error)
	GetFingerprintSensorInfo() (ctaptypes.AuthenticatorBioEnrollmentResponse, error)
	EnrollBegin(pinUvAuthToken []byte, timeoutMilliseconds uint) (ctaptypes.AuthenticatorBioEnrollmentResponse, error)
	EnrollCaptureNextSample(pinUvAuthToken []byte, templateID []byte, timeoutMilliseconds uint) (ctaptypes.AuthenticatorBioEnrollmentResponse, error)
	CancelCurrentEnrollment() error
	EnumerateEnrollments(pinUvAuthToken []byte) (ctaptypes.AuthenticatorBioEnrollmentResponse, error)
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
