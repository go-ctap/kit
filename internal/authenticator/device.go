package authenticator

import (
	"context"
	"iter"

	"github.com/go-ctap/ctap/attestation"
	ctapauthenticator "github.com/go-ctap/ctap/authenticator"
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
	GetPinUvAuthTokenUsingPIN(ctx context.Context, pin string, permission protocol.Permission, rpID string) ([]byte, error)
	GetPinUvAuthTokenUsingUV(ctx context.Context, permission protocol.Permission, rpID string) ([]byte, error)
	GetPINRetries(ctx context.Context) (uint, *bool, error)
}

type CredentialManager interface {
	InfoProvider
	GetCredsMetadata(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorCredentialManagementResponse, error)
	EnumerateRPs(ctx context.Context, pinUvAuthToken []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error]
	EnumerateCredentials(ctx context.Context, pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error]
	GetPersistentCredentialStoreState(ctx context.Context, pinUvAuthToken []byte) (ctapauthenticator.PersistentCredentialStoreState, error)
	DeleteCredential(ctx context.Context, pinUvAuthToken []byte, credentialID credential.PublicKeyCredentialDescriptor) error
	UpdateUserInformation(ctx context.Context, pinUvAuthToken []byte, credentialID credential.PublicKeyCredentialDescriptor, user credential.PublicKeyCredentialUserEntity) error
}

type WebAuthnManager interface {
	InfoProvider
	MakeCredential(
		ctx context.Context,
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
		ctx context.Context,
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
	GetLargeBlobs(ctx context.Context) ([]protocol.LargeBlob, error)
	SetLargeBlobs(ctx context.Context, pinUvAuthToken []byte, blobs []protocol.LargeBlob) error
}

type ConfigManager interface {
	GetPINRetries(ctx context.Context) (uint, *bool, error)
	GetUVRetries(ctx context.Context) (uint, error)
	SetPIN(ctx context.Context, pin string) error
	ChangePIN(ctx context.Context, currentPin, newPin string) error
	Reset(ctx context.Context) error
	ToggleAlwaysUV(ctx context.Context, pinUvAuthToken []byte) error
	SetMinPINLength(ctx context.Context, pinUvAuthToken []byte, params protocol.SetMinPINLengthConfigSubCommandParams) error
	EnableLongTouchForReset(ctx context.Context, pinUvAuthToken []byte) error
}

type BioEnrollmentManager interface {
	GetBioModality(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error)
	GetFingerprintSensorInfo(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error)
	EnrollBegin(ctx context.Context, pinUvAuthToken []byte, timeoutMilliseconds uint) (protocol.AuthenticatorBioEnrollmentResponse, error)
	EnrollCaptureNextSample(ctx context.Context, pinUvAuthToken []byte, templateID []byte, timeoutMilliseconds uint) (protocol.AuthenticatorBioEnrollmentResponse, error)
	CancelCurrentEnrollment(ctx context.Context) error
	EnumerateEnrollments(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorBioEnrollmentResponse, error)
	SetFriendlyName(ctx context.Context, pinUvAuthToken []byte, templateID []byte, name string) error
	RemoveEnrollment(ctx context.Context, pinUvAuthToken []byte, templateID []byte) error
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
