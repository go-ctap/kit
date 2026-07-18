package ctapkit

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"sync/atomic"

	"github.com/go-ctap/ctap/attestation"
	ctapdevice "github.com/go-ctap/ctap/authenticator"
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

func (a *contractAuthenticator) GetPinUvAuthTokenUsingPIN(context.Context, string, protocol.Permission, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {}
}

func (a *contractAuthenticator) EnumerateCredentials(context.Context, []byte, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {}
}

func (a *contractAuthenticator) DeleteCredential(context.Context, []byte, credential.PublicKeyCredentialDescriptor) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) UpdateUserInformation(context.Context, []byte, credential.PublicKeyCredentialDescriptor, credential.PublicKeyCredentialUserEntity) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) MakeCredential(
	context.Context,
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
	context.Context,
	[]byte,
	string,
	[]byte,
	[]credential.PublicKeyCredentialDescriptor,
	*webauthn.GetAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {}
}

func (a *contractAuthenticator) GetLargeBlobs(context.Context) ([]protocol.LargeBlob, error) {
	return nil, errors.New("not implemented")
}

func (a *contractAuthenticator) SetLargeBlobs(context.Context, []byte, []protocol.LargeBlob) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) GetPINRetries(context.Context) (uint, *bool, error) {
	return 0, nil, nil
}
func (a *contractAuthenticator) GetUVRetries(context.Context) (uint, error) { return 0, nil }
func (a *contractAuthenticator) SetPIN(context.Context, string) error {
	return errors.New("not implemented")
}
func (a *contractAuthenticator) ChangePIN(context.Context, string, string) error {
	return errors.New("not implemented")
}
func (a *contractAuthenticator) Reset(context.Context) error { return errors.New("not implemented") }
func (a *contractAuthenticator) ToggleAlwaysUV(context.Context, []byte) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) SetMinPINLength(context.Context, []byte, protocol.SetMinPINLengthConfigSubCommandParams) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) EnableLongTouchForReset(context.Context, []byte) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) GetPersistentCredentialStoreState(context.Context, []byte) (ctapdevice.PersistentCredentialStoreState, error) {
	return ctapdevice.PersistentCredentialStoreState{}, errors.New("not implemented")
}

func (a *contractAuthenticator) GetBioModality(context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) GetFingerprintSensorInfo(context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnrollBegin(context.Context, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) EnrollCaptureNextSample(context.Context, []byte, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) CancelCurrentEnrollment(context.Context) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) EnumerateEnrollments(context.Context, []byte) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{}, errors.New("not implemented")
}

func (a *contractAuthenticator) SetFriendlyName(context.Context, []byte, []byte, string) error {
	return errors.New("not implemented")
}

func (a *contractAuthenticator) RemoveEnrollment(context.Context, []byte, []byte) error {
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

func (a *pinMutationCountingAuthenticator) SetPIN(context.Context, string) error {
	a.setCalls.Add(1)

	return a.setErr
}

func (a *pinMutationCountingAuthenticator) ChangePIN(context.Context, string, string) error {
	a.changeCalls.Add(1)

	return a.changeErr
}

func (a *resetCountingAuthenticator) Reset(context.Context) error {
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

func (a *uvTokenAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
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

func (a *uvTokenAuthenticator) ToggleAlwaysUV(_ context.Context, token []byte) error {
	if token == nil {
		return ctapdevice.ErrPinUvAuthTokenRequired
	}

	return nil
}

type largeBlobWriteEventAuthenticator struct {
	contractAuthenticator
	setErr                       error
	rpErr                        error
	largeBlobReadErr             error
	cancelLargeBlobRead          context.CancelFunc
	omitLargeBlobKey             bool
	largeBlobs                   []protocol.LargeBlob
	lastSetLargeBlobs            []protocol.LargeBlob
	maxSerializedLargeBlobArray  uint
	rpEnumerations               atomic.Int32
	credentialEnumerations       atomic.Int32
	tokenCalls                   atomic.Int32
	tokenPermissions             []protocol.Permission
	credentialManagementReadOnly bool
	largeBlobReads               atomic.Int32
	largeBlobWrites              atomic.Int32
}

func (a *largeBlobWriteEventAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	options := map[protocol.Option]bool{
		protocol.OptionCredentialManagement: true,
		protocol.OptionLargeBlobs:           true,
		protocol.OptionPinUvAuthToken:       true,
		protocol.OptionUserVerification:     true,
	}

	if a.credentialManagementReadOnly {
		options[protocol.OptionCredentialManagementReadOnly] = true
	}

	return protocol.AuthenticatorGetInfoResponse{
		Options:                     options,
		MaxSerializedLargeBlobArray: a.maxSerializedLargeBlobArray,
	}
}

func (a *largeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	permission protocol.Permission,
	_ string,
) ([]byte, error) {
	a.tokenCalls.Add(1)
	a.tokenPermissions = append(a.tokenPermissions, permission)

	return []byte("token"), nil
}

func (a *largeBlobWriteEventAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(1)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(10)),
	}, nil
}

func (a *largeBlobWriteEventAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		a.rpEnumerations.Add(1)
		if a.rpErr != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, a.rpErr)

			return
		}
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "id.example", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *largeBlobWriteEventAuthenticator) EnumerateCredentials(context.Context, []byte, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		a.credentialEnumerations.Add(1)
		var largeBlobKey []byte
		if !a.omitLargeBlobKey {
			largeBlobKey = bytes.Repeat([]byte{0x01}, 32)
		}
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
			LargeBlobKey:     largeBlobKey,
			TotalCredentials: 1,
		}, nil)
	}
}

func (a *largeBlobWriteEventAuthenticator) GetLargeBlobs(context.Context) ([]protocol.LargeBlob, error) {
	a.largeBlobReads.Add(1)

	if a.cancelLargeBlobRead != nil {
		a.cancelLargeBlobRead()
	}

	if a.largeBlobReadErr != nil {
		return nil, a.largeBlobReadErr
	}

	return a.largeBlobs, nil
}

func (a *largeBlobWriteEventAuthenticator) SetLargeBlobs(_ context.Context, _ []byte, blobs []protocol.LargeBlob) error {
	a.largeBlobWrites.Add(1)
	a.lastSetLargeBlobs = blobs

	return a.setErr
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
	context.Context,
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
	context.Context,
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
	context.Context,
	string,
	protocol.Permission,
	string,
) ([]byte, error) {
	a.pinCalls.Add(1)

	return []byte("token"), nil
}

func (a *pinPreferredLargeBlobWriteEventAuthenticator) GetPinUvAuthTokenUsingUV(
	context.Context,
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

type blockingConfigAuthenticator struct {
	contractAuthenticator
	commandEntered chan struct{}
}

func (a *blockingConfigAuthenticator) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionAuthenticatorConfig: true,
		protocol.OptionPinUvAuthToken:      true,
		protocol.OptionUserVerification:    true,
		protocol.OptionUvAcfg:              true,
		protocol.OptionAlwaysUv:            false,
	}}
}

func (a *blockingConfigAuthenticator) GetPinUvAuthTokenUsingUV(
	context.Context,
	protocol.Permission,
	string,
) ([]byte, error) {
	return []byte("token"), nil
}

func (a *blockingConfigAuthenticator) ToggleAlwaysUV(ctx context.Context, token []byte) error {
	if token == nil {
		return ctapdevice.ErrPinUvAuthTokenRequired
	}

	close(a.commandEntered)
	<-ctx.Done()

	return ctx.Err()
}

func (a *cancelablePINAuthenticator) Close() error {
	if a.closeCount.Add(1) == 1 {
		close(a.closeStarted)
	}

	return nil
}
