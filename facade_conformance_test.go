package ctapkit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	appoperation "github.com/telesma-app/kit/model/operation"
	"github.com/telesma-app/kit/transport"
)

func TestRunCTAP23ConformanceSafeUsesSelectedAuthenticatorWithoutReset(t *testing.T) {
	info := facadeConformanceInfo()
	raw := newFacadeConformanceCBOR(t, info, info, info)
	device := &facadeConformanceAuthenticator{info: info}
	opened := openFacadeConformanceAuthenticator(t, device, raw)

	result, err := opened.RunCTAP23Conformance(t.Context(), ctap23.RunRequest{
		Metadata: ctap23.Metadata{
			GetInfo:                 info,
			GetInfoFields:           []uint64{1, 2, 3},
			UserVerificationMethods: protocol.UserVerifyPresenceInternal,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusPassed || len(result.Tests) != 3 {
		t.Fatalf("result = %#v, want three safe tests", result)
	}
	if result.Tests[2].ID != ctap23.TestIDAuthrGeneric1P3 || result.Tests[2].Status != conformance.StatusSkipped {
		t.Fatalf("P-3 result = %#v", result.Tests[2])
	}
	if device.resetCalls != 0 || device.setPINCalls != 0 || device.pinTokenCalls != 0 {
		t.Fatalf("destructive calls = reset %d, set PIN %d, token %d", device.resetCalls, device.setPINCalls, device.pinTokenCalls)
	}
	if len(raw.commands) != 3 {
		t.Fatalf("raw commands = %x, want three GetInfo commands", raw.commands)
	}
}

func TestRunCTAP23ConformanceFullRoutesPINAndResetThroughRuntime(t *testing.T) {
	token := make([]byte, 32)
	for index := range token {
		token[index] = byte(index + 1)
	}

	initial := facadeConformanceInfo()
	initial.Options = map[protocol.Option]bool{
		protocol.OptionClientPIN:      false,
		protocol.OptionPinUvAuthToken: true,
	}
	initial.MinPINLength = 4
	initial.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}

	identifierBefore := [aes.BlockSize]byte{1, 2, 3, 4}
	identifierAfter := [aes.BlockSize]byte{5, 6, 7, 8}
	stateBefore := [aes.BlockSize]byte{9, 10, 11, 12}
	stateAfter := [aes.BlockSize]byte{13, 14, 15, 16}
	infos := make([]protocol.AuthenticatorGetInfoResponse, 11)
	for index := range infos {
		infos[index] = initial

		identifier := identifierBefore
		if index >= 6 {
			identifier = identifierAfter
		}
		state := stateBefore
		if index >= 10 {
			state = stateAfter
		}
		infos[index].EncIdentifier = encryptFacadeConformanceMember(
			t,
			token,
			identifier,
			facadeConformanceIV(byte(2*index+1)),
			"encIdentifier",
		)
		infos[index].EncCredStoreState = encryptFacadeConformanceMember(
			t,
			token,
			state,
			facadeConformanceIV(byte(2*index+2)),
			"encCredStoreState",
		)
	}

	raw := newFacadeConformanceCBOR(t, infos...)
	wantToken := slices.Clone(token)
	device := &facadeConformanceAuthenticator{
		info:  initial,
		token: token,
	}
	opened := openFacadeConformanceAuthenticator(t, device, raw)

	var interactions []model.InteractionRequest
	handler := interactionHandlerFunc(func(request model.InteractionRequest) (model.InteractionResponse, error) {
		interactions = append(interactions, request)
		if request.Kind == model.InteractionKindPIN {
			return model.InteractionResponse{PIN: []byte("123456")}, nil
		}

		return model.InteractionResponse{}, nil
	})
	result, err := opened.RunCTAP23Conformance(
		t.Context(),
		ctap23.RunRequest{
			Mode: ctap23.RunModeFull,
			Metadata: ctap23.Metadata{
				GetInfo:                 infos[0],
				GetInfoFields:           []uint64{1, 2, 3, 4, 6, 13, 25, 30},
				UserVerificationMethods: protocol.UserVerifyPresenceInternal | protocol.UserVerifyPasscodeExternal,
			},
		},
		WithInteractionHandler(handler),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusPassed || len(result.Tests) != 5 {
		t.Fatalf("result = %#v, want five passed tests", result)
	}
	for _, testResult := range result.Tests {
		if testResult.Status != conformance.StatusPassed {
			t.Fatalf("test %q = %#v, want passed", testResult.ID, testResult)
		}
	}
	if device.resetCalls != 2 || device.setPINCalls != 2 || device.pinTokenCalls != 2 {
		t.Fatalf("runtime calls = reset %d, set PIN %d, token %d; want 2 each", device.resetCalls, device.setPINCalls, device.pinTokenCalls)
	}
	wantInteractionKinds := []model.InteractionKind{
		model.InteractionKindPIN,
		model.InteractionKindTouch,
		model.InteractionKindPIN,
		model.InteractionKindTouch,
	}
	interactionKinds := make([]model.InteractionKind, len(interactions))
	for index, interaction := range interactions {
		interactionKinds[index] = interaction.Kind
		if interaction.Kind == model.InteractionKindTouch && !interaction.Destructive {
			t.Fatalf("touch interaction %d is not marked destructive", index)
		}
	}
	if !slices.Equal(interactionKinds, wantInteractionKinds) {
		t.Fatalf("interaction kinds = %v, want %v", interactionKinds, wantInteractionKinds)
	}
	if len(raw.commands) != 11 {
		t.Fatalf("raw commands = %x, want eleven GetInfo commands", raw.commands)
	}
	if !slices.Equal(device.token, wantToken) {
		t.Fatal("device-owned token was mutated")
	}
}

func TestRunCTAP23ConformanceRejectsInvalidModeBeforeDeviceAccess(t *testing.T) {
	opened := &Authenticator{}
	result, err := opened.RunCTAP23Conformance(t.Context(), ctap23.RunRequest{
		Mode: "invalid",
	})
	if !failure.IsCode(err, failure.CodeConformanceModeInvalid) {
		t.Fatalf("error = %v, want conformance mode failure", err)
	}
	normalized := failure.Snapshot(err)
	if normalized.Operation != string(appoperation.ConformanceCTAP23) || normalized.Phase != failure.PhaseValidation {
		t.Fatalf("failure = %#v, want conformance validation operation", normalized)
	}
	requireZero(t, result)
}

type facadeConformanceAuthenticator struct {
	contractAuthenticator
	info          protocol.AuthenticatorGetInfoResponse
	token         []byte
	configured    bool
	resetCalls    int
	setPINCalls   int
	pinTokenCalls int
}

func (a *facadeConformanceAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return a.info, true
}

func (a *facadeConformanceAuthenticator) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return a.info, nil
}

func (a *facadeConformanceAuthenticator) SetPIN(_ context.Context, pin string) error {
	if pin != "123456" {
		return fmt.Errorf("unexpected conformance PIN")
	}

	a.setPINCalls++
	a.configured = true
	a.info.Options[protocol.OptionClientPIN] = true

	return nil
}

func (a *facadeConformanceAuthenticator) GetPinUvAuthTokenUsingPIN(
	_ context.Context,
	pin string,
	permission protocol.Permission,
	_ string,
) ([]byte, error) {
	if !a.configured || pin != "123456" {
		return nil, fmt.Errorf("PIN is not configured")
	}
	if permission != protocol.PermissionPersistentCredentialManagementReadOnly {
		return nil, fmt.Errorf("permission = %v", permission)
	}

	a.pinTokenCalls++

	return slices.Clone(a.token), nil
}

func (a *facadeConformanceAuthenticator) Reset(context.Context) error {
	a.resetCalls++
	a.configured = false
	a.info.Options[protocol.OptionClientPIN] = false

	return nil
}

type facadeConformanceCBOR struct {
	t         *testing.T
	responses [][]byte
	commands  []protocol.Command
}

func newFacadeConformanceCBOR(
	t *testing.T,
	infos ...protocol.AuthenticatorGetInfoResponse,
) *facadeConformanceCBOR {
	t.Helper()

	responses := make([][]byte, len(infos))
	for index, info := range infos {
		responses[index] = encodeFacadeConformanceCBOR(t, info)
	}

	return &facadeConformanceCBOR{t: t, responses: responses}
}

func (cbor *facadeConformanceCBOR) CBOR(
	_ context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	if len(data) != 1 || protocol.Command(data[0]) != protocol.AuthenticatorGetInfo {
		return ctaptransport.CBORResponse{}, fmt.Errorf("unexpected conformance command %x", data)
	}

	index := len(cbor.commands)
	if index >= len(cbor.responses) {
		cbor.t.Fatalf("unexpected GetInfo call %d", index+1)
	}
	cbor.commands = append(cbor.commands, protocol.AuthenticatorGetInfo)

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       cbor.responses[index],
	}, nil
}

func openFacadeConformanceAuthenticator(
	t *testing.T,
	device *facadeConformanceAuthenticator,
	cbor ctaptransport.CBOR,
) *Authenticator {
	t.Helper()

	opened, err := openAuthenticatorHandle(
		t.Context(),
		newContractDevice(),
		func(context.Context, transport.Mode, string) (*authenticator.Opened, error) {
			capabilities := contractOpened(device)
			capabilities.CBOR = cbor

			return capabilities, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return opened
}

func facadeConformanceInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		AAGUID:     uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff"),
	}
}

func encodeFacadeConformanceCBOR(t *testing.T, value any) []byte {
	t.Helper()

	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	data, err := mode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func encryptFacadeConformanceMember(
	t *testing.T,
	token []byte,
	plaintext [aes.BlockSize]byte,
	initializationVector [aes.BlockSize]byte,
	label string,
) []byte {
	t.Helper()

	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	_, _ = extract.Write(token)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	_, _ = expand.Write([]byte(label))
	_, _ = expand.Write([]byte{1})
	key := expand.Sum(nil)[:aes.BlockSize]

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	encrypted := make([]byte, 2*aes.BlockSize)
	copy(encrypted, initializationVector[:])
	cipher.NewCBCEncrypter(block, initializationVector[:]).CryptBlocks(encrypted[aes.BlockSize:], plaintext[:])

	return encrypted
}

func facadeConformanceIV(value byte) [aes.BlockSize]byte {
	var initializationVector [aes.BlockSize]byte
	for index := range initializationVector {
		initializationVector[index] = value
	}

	return initializationVector
}
