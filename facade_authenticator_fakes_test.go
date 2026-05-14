package ctapkit

import (
	"bytes"
	"errors"
	"iter"
	"sync/atomic"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model"
)

type contractAuthenticator struct{}

func (a *contractAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}}
}

func (a *contractAuthenticator) Close() error { return nil }

func (a *contractAuthenticator) GetPinUvAuthTokenUsingPIN(string, protocol.Permission, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) GetPinUvAuthTokenUsingUV(protocol.Permission, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) GetCredsMetadata([]byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnumerateRPs([]byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {}
}

func (a *contractAuthenticator) EnumerateCredentials([]byte, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {}
}

func (a *contractAuthenticator) DeleteCredential([]byte, credential.PublicKeyCredentialDescriptor) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) UpdateUserInformation([]byte, credential.PublicKeyCredentialDescriptor, credential.PublicKeyCredentialUserEntity) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) MakeCredential(
	[]byte,
	[]byte,
	credential.PublicKeyCredentialRpEntity,
	credential.PublicKeyCredentialUserEntity,
	[]credential.PublicKeyCredentialParameters,
	[]credential.PublicKeyCredentialDescriptor,
	*webauthn.CreateAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
	uint,
	[]attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return protocol.AuthenticatorMakeCredentialResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) GetAssertion(
	[]byte,
	string,
	[]byte,
	[]credential.PublicKeyCredentialDescriptor,
	*webauthn.GetAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {}
}

func (a *contractAuthenticator) GetLargeBlobs() ([]protocol.LargeBlob, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) SetLargeBlobs([]byte, []protocol.LargeBlob) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) GetPINRetries() (uint, *bool, error) { return 0, nil, nil }
func (a *contractAuthenticator) GetUVRetries() (uint, error)         { return 0, nil }
func (a *contractAuthenticator) SetPIN(string) error                 { return errors.New("not implemented") }
func (a *contractAuthenticator) ChangePIN(string, string) error      { return errors.New("not implemented") }
func (a *contractAuthenticator) Reset() error                        { return errors.New("not implemented") }
func (a *contractAuthenticator) ToggleAlwaysUV([]byte) error         { return errors.New("not implemented") }

func (a *contractAuthenticator) SetMinPINLength([]byte, uint, []string, bool, bool) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) GetBioModality() (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) GetFingerprintSensorInfo() (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnrollBegin([]byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnrollCaptureNextSample([]byte, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) CancelCurrentEnrollment() error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) EnumerateEnrollments([]byte) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) SetFriendlyName([]byte, []byte, string) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) RemoveEnrollment([]byte, []byte) error {
	return errors.New("not implemented")
}

type closeCountingAuthenticator struct {
	contractAuthenticator
	closeStarted chan struct{}
	releaseClose chan struct{}
	closeCount   atomic.Int32
}

func (a *closeCountingAuthenticator) Close() error {
	if a.closeCount.Add(1) == 1 {
		close(a.closeStarted)
		<-a.releaseClose
	}

	return nil
}

type resetCountingAuthenticator struct {
	contractAuthenticator
	events               *recordingEventSink
	resetErr             error
	resetCount           atomic.Int32
	touchSeenBeforeReset atomic.Bool
}

type pinMutationCountingAuthenticator struct {
	contractAuthenticator
	configured  bool
	setErr      error
	changeErr   error
	setCalls    atomic.Int32
	changeCalls atomic.Int32
}

func (a *pinMutationCountingAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: a.configured,
		},
	}
}

func (a *pinMutationCountingAuthenticator) SetPIN(string) error {
	a.setCalls.Add(1)

	return a.setErr
}

func (a *pinMutationCountingAuthenticator) ChangePIN(string, string) error {
	a.changeCalls.Add(1)

	return a.changeErr
}

func (a *resetCountingAuthenticator) Reset() error {
	if a.events != nil {
		for _, event := range a.events.Events() {
			if event.Stage == model.OperationStageInteractionRequired &&
				event.Kind == model.InteractionKindTouch {
				a.touchSeenBeforeReset.Store(true)

				break
			}
		}
	}

	a.resetCount.Add(1)

	return a.resetErr
}

type uvTokenAuthenticator struct {
	contractAuthenticator
	events               *recordingEventSink
	uvCalled             atomic.Bool
	userVerificationSeen atomic.Bool
}

func (a *uvTokenAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:      true,
			protocol.OptionUserVerification:    true,
			protocol.OptionAuthenticatorConfig: true,
			protocol.OptionUvAcfg:              true,
			protocol.OptionAlwaysUv:            false,
		},
	}
}

func (a *uvTokenAuthenticator) GetPinUvAuthTokenUsingUV(protocol.Permission, string) ([]byte, error) {
	for _, event := range a.events.Events() {
		if event.Stage == model.OperationStageInteractionRequired &&
			event.Kind == model.InteractionKindUserVerification {
			a.userVerificationSeen.Store(true)

			break
		}
	}

	a.uvCalled.Store(true)

	return []byte("token"), nil
}

func (a *uvTokenAuthenticator) ToggleAlwaysUV([]byte) error {
	return nil
}

type largeBlobWriteEventAuthenticator struct {
	contractAuthenticator
	setErr                      error
	largeBlobs                  []protocol.LargeBlob
	lastSetLargeBlobs           []protocol.LargeBlob
	maxSerializedLargeBlobArray uint
	rpEnumerations              atomic.Int32
	credentialEnumerations      atomic.Int32
	largeBlobReads              atomic.Int32
	largeBlobWrites             atomic.Int32
}

func (a *largeBlobWriteEventAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionLargeBlobs:           true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
		MaxSerializedLargeBlobArray: new(a.maxSerializedLargeBlobArray),
	}
}

func (a *largeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *largeBlobWriteEventAuthenticator) GetCredsMetadata([]byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             1,
		MaxPossibleRemainingResidentCredentialsCount: 10,
	}, nil
}

func (a *largeBlobWriteEventAuthenticator) EnumerateRPs([]byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		a.rpEnumerations.Add(1)
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "id.example", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *largeBlobWriteEventAuthenticator) EnumerateCredentials([]byte, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		a.credentialEnumerations.Add(1)
		yield(protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "savely",
				DisplayName: "Savely",
			},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte{0xc0, 0x5e},
			},
			LargeBlobKey: bytes.Repeat([]byte{0x01}, 32),
		}, nil)
	}
}

func (a *largeBlobWriteEventAuthenticator) GetLargeBlobs() ([]protocol.LargeBlob, error) {
	a.largeBlobReads.Add(1)

	return cloneTestLargeBlobs(a.largeBlobs), nil
}

func (a *largeBlobWriteEventAuthenticator) SetLargeBlobs(_ []byte, blobs []protocol.LargeBlob) error {
	a.largeBlobWrites.Add(1)
	a.lastSetLargeBlobs = cloneTestLargeBlobs(blobs)

	return a.setErr
}

func cloneTestLargeBlobs(blobs []protocol.LargeBlob) []protocol.LargeBlob {
	if blobs == nil {
		return nil
	}

	cloned := make([]protocol.LargeBlob, 0, len(blobs))
	for _, blob := range blobs {
		cloned = append(cloned, protocol.LargeBlob{
			Ciphertext: append([]byte(nil), blob.Ciphertext...),
			Nonce:      append([]byte(nil), blob.Nonce...),
			OrigSize:   blob.OrigSize,
		})
	}

	return cloned
}

type pinOnlyLargeBlobWriteEventAuthenticator struct {
	largeBlobWriteEventAuthenticator
	pinCalls atomic.Int32
	uvCalls  atomic.Int32
	pinErr   error
}

func (a *pinOnlyLargeBlobWriteEventAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionLargeBlobs:           true,
			protocol.OptionClientPIN:            true,
			protocol.OptionPinUvAuthToken:       true,
		},
	}
}

func (a *pinOnlyLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingPIN(
	string,
	protocol.Permission,
	string,
) ([]byte, error) {
	a.pinCalls.Add(1)

	if a.pinErr != nil {
		return nil, a.pinErr
	}

	return []byte("token"), nil
}

func (a *pinOnlyLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(
	protocol.Permission,
	string,
) ([]byte, error) {
	a.uvCalls.Add(1)

	return nil, errors.New("UV token acquisition should not run for PIN-only authenticator")
}

type pinPreferredLargeBlobWriteEventAuthenticator struct {
	largeBlobWriteEventAuthenticator
	pinCalls atomic.Int32
	uvCalls  atomic.Int32
}

func (a *pinPreferredLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingPIN(
	string,
	protocol.Permission,
	string,
) ([]byte, error) {
	a.pinCalls.Add(1)

	return []byte("token"), nil
}

func (a *pinPreferredLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(
	protocol.Permission,
	string,
) ([]byte, error) {
	a.uvCalls.Add(1)

	return nil, errors.New("UV token acquisition should not run for PIN verification flow")
}

type cancelablePINAuthenticator struct {
	pinOnlyLargeBlobWriteEventAuthenticator
	closeStarted chan struct{}
	closeCount   atomic.Int32
}

func (a *cancelablePINAuthenticator) Close() error {
	if a.closeCount.Add(1) == 1 {
		close(a.closeStarted)
	}

	return nil
}
