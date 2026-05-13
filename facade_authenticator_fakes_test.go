package ctapkit

import (
	"bytes"
	"errors"
	"iter"
	"sync/atomic"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/model"
)

type contractAuthenticator struct{}

func (a *contractAuthenticator) GetInfo() ctaptypes.AuthenticatorGetInfoResponse {
	return ctaptypes.AuthenticatorGetInfoResponse{Options: map[ctaptypes.Option]bool{}}
}

func (a *contractAuthenticator) Close() error { return nil }

func (a *contractAuthenticator) GetPinUvAuthTokenUsingPIN(string, ctaptypes.Permission, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) GetPinUvAuthTokenUsingUV(ctaptypes.Permission, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) GetCredsMetadata([]byte) (ctaptypes.AuthenticatorCredentialManagementResponse, error) {
	return ctaptypes.AuthenticatorCredentialManagementResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnumerateRPs([]byte) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {}
}

func (a *contractAuthenticator) EnumerateCredentials([]byte, []byte) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {}
}

func (a *contractAuthenticator) DeleteCredential([]byte, webauthntypes.PublicKeyCredentialDescriptor) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) UpdateUserInformation([]byte, webauthntypes.PublicKeyCredentialDescriptor, webauthntypes.PublicKeyCredentialUserEntity) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) MakeCredential(
	[]byte,
	[]byte,
	webauthntypes.PublicKeyCredentialRpEntity,
	webauthntypes.PublicKeyCredentialUserEntity,
	[]webauthntypes.PublicKeyCredentialParameters,
	[]webauthntypes.PublicKeyCredentialDescriptor,
	*webauthntypes.CreateAuthenticationExtensionsClientInputs,
	map[ctaptypes.Option]bool,
	uint,
	[]webauthntypes.AttestationStatementFormatIdentifier,
) (ctaptypes.AuthenticatorMakeCredentialResponse, error) {
	return ctaptypes.AuthenticatorMakeCredentialResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) GetAssertion(
	[]byte,
	string,
	[]byte,
	[]webauthntypes.PublicKeyCredentialDescriptor,
	*webauthntypes.GetAuthenticationExtensionsClientInputs,
	map[ctaptypes.Option]bool,
) iter.Seq2[ctaptypes.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorGetAssertionResponse, error) bool) {}
}

func (a *contractAuthenticator) GetLargeBlobs() ([]ctaptypes.LargeBlob, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) SetLargeBlobs([]byte, []ctaptypes.LargeBlob) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) GetPINRetries() (uint, bool, error) { return 0, false, nil }
func (a *contractAuthenticator) GetUVRetries() (uint, error)        { return 0, nil }
func (a *contractAuthenticator) SetPIN(string) error                { return errors.New("not implemented") }
func (a *contractAuthenticator) ChangePIN(string, string) error     { return errors.New("not implemented") }
func (a *contractAuthenticator) Reset() error                       { return errors.New("not implemented") }
func (a *contractAuthenticator) ToggleAlwaysUV([]byte) error        { return errors.New("not implemented") }

func (a *contractAuthenticator) SetMinPINLength([]byte, uint, []string, bool, bool) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) GetBioModality() (ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	return ctaptypes.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) GetFingerprintSensorInfo() (ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	return ctaptypes.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnrollBegin([]byte, uint) (ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	return ctaptypes.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnrollCaptureNextSample([]byte, []byte, uint) (ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	return ctaptypes.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) CancelCurrentEnrollment() error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) EnumerateEnrollments([]byte) (ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	return ctaptypes.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
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

func (a *pinMutationCountingAuthenticator) GetInfo() ctaptypes.AuthenticatorGetInfoResponse {
	return ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionClientPIN: a.configured,
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

func (a *uvTokenAuthenticator) GetInfo() ctaptypes.AuthenticatorGetInfoResponse {
	return ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionPinUvAuthToken:      true,
			ctaptypes.OptionUserVerification:    true,
			ctaptypes.OptionAuthenticatorConfig: true,
			ctaptypes.OptionUvAcfg:              true,
			ctaptypes.OptionAlwaysUv:            false,
		},
	}
}

func (a *uvTokenAuthenticator) GetPinUvAuthTokenUsingUV(ctaptypes.Permission, string) ([]byte, error) {
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
	largeBlobs                  []ctaptypes.LargeBlob
	lastSetLargeBlobs           []ctaptypes.LargeBlob
	maxSerializedLargeBlobArray uint
	rpEnumerations              atomic.Int32
	credentialEnumerations      atomic.Int32
	largeBlobReads              atomic.Int32
	largeBlobWrites             atomic.Int32
}

func (a *largeBlobWriteEventAuthenticator) GetInfo() ctaptypes.AuthenticatorGetInfoResponse {
	return ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionCredentialManagement: true,
			ctaptypes.OptionLargeBlobs:           true,
			ctaptypes.OptionPinUvAuthToken:       true,
			ctaptypes.OptionUserVerification:     true,
		},
		MaxSerializedLargeBlobArray: new(a.maxSerializedLargeBlobArray),
	}
}

func (a *largeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(ctaptypes.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *largeBlobWriteEventAuthenticator) GetCredsMetadata([]byte) (ctaptypes.AuthenticatorCredentialManagementResponse, error) {
	return ctaptypes.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             1,
		MaxPossibleRemainingResidentCredentialsCount: 10,
	}, nil
}

func (a *largeBlobWriteEventAuthenticator) EnumerateRPs([]byte) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		a.rpEnumerations.Add(1)
		yield(ctaptypes.AuthenticatorCredentialManagementResponse{
			RP:       webauthntypes.PublicKeyCredentialRpEntity{ID: "id.example", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *largeBlobWriteEventAuthenticator) EnumerateCredentials([]byte, []byte) iter.Seq2[ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		a.credentialEnumerations.Add(1)
		yield(ctaptypes.AuthenticatorCredentialManagementResponse{
			User: webauthntypes.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "savely",
				DisplayName: "Savely",
			},
			CredentialID: webauthntypes.PublicKeyCredentialDescriptor{
				Type: webauthntypes.PublicKeyCredentialTypePublicKey,
				ID:   []byte{0xc0, 0x5e},
			},
			LargeBlobKey: bytes.Repeat([]byte{0x01}, 32),
		}, nil)
	}
}

func (a *largeBlobWriteEventAuthenticator) GetLargeBlobs() ([]ctaptypes.LargeBlob, error) {
	a.largeBlobReads.Add(1)

	return cloneTestLargeBlobs(a.largeBlobs), nil
}

func (a *largeBlobWriteEventAuthenticator) SetLargeBlobs(_ []byte, blobs []ctaptypes.LargeBlob) error {
	a.largeBlobWrites.Add(1)
	a.lastSetLargeBlobs = cloneTestLargeBlobs(blobs)

	return a.setErr
}

func cloneTestLargeBlobs(blobs []ctaptypes.LargeBlob) []ctaptypes.LargeBlob {
	if blobs == nil {
		return nil
	}

	cloned := make([]ctaptypes.LargeBlob, 0, len(blobs))
	for _, blob := range blobs {
		cloned = append(cloned, ctaptypes.LargeBlob{
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

func (a *pinOnlyLargeBlobWriteEventAuthenticator) GetInfo() ctaptypes.AuthenticatorGetInfoResponse {
	return ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionCredentialManagement: true,
			ctaptypes.OptionLargeBlobs:           true,
			ctaptypes.OptionClientPIN:            true,
			ctaptypes.OptionPinUvAuthToken:       true,
		},
	}
}

func (a *pinOnlyLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingPIN(
	string,
	ctaptypes.Permission,
	string,
) ([]byte, error) {
	a.pinCalls.Add(1)

	if a.pinErr != nil {
		return nil, a.pinErr
	}

	return []byte("token"), nil
}

func (a *pinOnlyLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(
	ctaptypes.Permission,
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
	ctaptypes.Permission,
	string,
) ([]byte, error) {
	a.pinCalls.Add(1)

	return []byte("token"), nil
}

func (a *pinPreferredLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(
	ctaptypes.Permission,
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
