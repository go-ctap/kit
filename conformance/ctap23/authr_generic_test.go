package ctap23_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
)

func TestGetInfoP2ValidatesMetadataForUPAndUVOptions(t *testing.T) {
	tests := []struct {
		name    string
		options map[protocol.Option]bool
		methods protocol.UserVerify
		status  conformance.Status
	}{
		{
			name:    "default user presence",
			methods: protocol.UserVerifyPresenceInternal,
			status:  conformance.StatusPassed,
		},
		{
			name: "built-in user verification",
			options: map[protocol.Option]bool{
				protocol.OptionUserPresence:     true,
				protocol.OptionUserVerification: true,
			},
			methods: protocol.UserVerifyPresenceInternal | protocol.UserVerifyFingerprintInternal,
			status:  conformance.StatusPassed,
		},
		{
			name: "no user presence or verification",
			options: map[protocol.Option]bool{
				protocol.OptionUserPresence:     false,
				protocol.OptionUserVerification: false,
			},
			methods: protocol.UserVerifyNone,
			status:  conformance.StatusPassed,
		},
		{
			name: "missing user verification method",
			options: map[protocol.Option]bool{
				protocol.OptionUserPresence:     true,
				protocol.OptionUserVerification: true,
			},
			methods: protocol.UserVerifyPresenceInternal,
			status:  conformance.StatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := validGetInfo()
			info.Options = tt.options
			result := runSingleAuthenticatorTest(t, &cborDevice{
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_OK,
					Data:       encodeCBOR(t, info),
				},
			}, ctap23.Config{
				Metadata: ctap23.Metadata{UserVerificationMethods: tt.methods},
			}, ctap23.TestIDAuthrGeneric1P2)

			if result.Tests[0].Status != tt.status {
				t.Fatalf("test status = %q, want %q: %#v", result.Tests[0].Status, tt.status, result.Tests[0].Steps)
			}
		})
	}
}

func TestGetInfoP2RejectsNonBooleanOptionOnWire(t *testing.T) {
	info := validGetInfo()
	data := encodeCBOR(t, map[uint64]any{
		1: info.Versions,
		2: info.Extensions,
		3: info.AAGUID[:],
		4: map[string]any{"up": "yes"},
	})
	result := runSingleAuthenticatorTest(t, &cborDevice{
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       data,
		},
	}, ctap23.Config{}, ctap23.TestIDAuthrGeneric1P2)

	if result.Tests[0].Status != conformance.StatusFailed {
		t.Fatalf("test = %#v, want failed", result.Tests[0])
	}
}

func TestGetInfoP3RequiresExternalPasscodeMetadata(t *testing.T) {
	info := validGetInfo()
	info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}
	device := &cborDevice{response: ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       encodeCBOR(t, info),
	}}

	passed := runSingleAuthenticatorTest(t, device, ctap23.Config{
		Metadata: ctap23.Metadata{UserVerificationMethods: protocol.UserVerifyPasscodeExternal},
	}, ctap23.TestIDAuthrGeneric1P3)
	if passed.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("test = %#v, want passed", passed.Tests[0])
	}

	failed := runSingleAuthenticatorTest(t, device, ctap23.Config{}, ctap23.TestIDAuthrGeneric1P3)
	if failed.Tests[0].Status != conformance.StatusFailed {
		t.Fatalf("test = %#v, want failed", failed.Tests[0])
	}
}

func TestGetInfoP4AndP5ValidateEncryptedStateAndWipeToken(t *testing.T) {
	tests := []struct {
		name   string
		testID conformance.TestID
		label  string
		set    func(*protocol.AuthenticatorGetInfoResponse, []byte)
	}{
		{
			name:   "device identifier",
			testID: ctap23.TestIDAuthrGeneric1P4,
			label:  "encIdentifier",
			set: func(info *protocol.AuthenticatorGetInfoResponse, value []byte) {
				info.EncIdentifier = value
			},
		},
		{
			name:   "credential store state",
			testID: ctap23.TestIDAuthrGeneric1P5,
			label:  "encCredStoreState",
			set: func(info *protocol.AuthenticatorGetInfoResponse, value []byte) {
				info.EncCredStoreState = value
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := make([]byte, 32)
			for index := range token {
				token[index] = byte(index + 1)
			}
			stablePlaintext := [aes.BlockSize]byte{1, 2, 3, 4}
			resetPlaintext := [aes.BlockSize]byte{5, 6, 7, 8}

			infos := make([]protocol.AuthenticatorGetInfoResponse, 4)
			for index := range infos {
				infos[index] = validGetInfo()
			}
			tt.set(&infos[0], encryptGetInfoMember(t, token, stablePlaintext, iv(1), tt.label))
			tt.set(&infos[1], encryptGetInfoMember(t, token, stablePlaintext, iv(2), tt.label))
			tt.set(&infos[2], encryptGetInfoMember(t, token, stablePlaintext, iv(3), tt.label))
			tt.set(&infos[3], encryptGetInfoMember(t, token, resetPlaintext, iv(4), tt.label))

			device := newScriptedDevice(t, infos)
			providerCalls := 0
			result := runSingleAuthenticatorTest(t, device, ctap23.Config{
				PersistentTokenProvider: func(
					_ context.Context,
					_ *client.Client,
					permission protocol.Permission,
				) ([]byte, error) {
					providerCalls++
					if permission != protocol.PermissionPersistentCredentialManagementReadOnly {
						return nil, fmt.Errorf("permission = %v", permission)
					}

					return token, nil
				},
			}, tt.testID)

			if result.Tests[0].Status != conformance.StatusPassed {
				t.Fatalf("test = %#v, want passed", result.Tests[0])
			}
			if providerCalls != 1 {
				t.Fatalf("provider calls = %d, want 1", providerCalls)
			}
			if !slices.Equal(token, make([]byte, len(token))) {
				t.Fatalf("token was not wiped: %x", token)
			}
			wantCommands := []byte{
				byte(protocol.AuthenticatorGetInfo),
				byte(protocol.AuthenticatorGetInfo),
				byte(protocol.AuthenticatorGetInfo),
				byte(protocol.AuthenticatorReset),
				byte(protocol.AuthenticatorGetInfo),
			}
			if !slices.Equal(device.commands, wantCommands) {
				t.Fatalf("commands = %x, want %x", device.commands, wantCommands)
			}
		})
	}
}

func TestGetInfoP4RequiresTokenProviderWhenIdentifierIsAdvertised(t *testing.T) {
	info := validGetInfo()
	info.EncIdentifier = make([]byte, 32)
	result := runSingleAuthenticatorTest(
		t,
		newScriptedDevice(t, []protocol.AuthenticatorGetInfoResponse{info}),
		ctap23.Config{},
		ctap23.TestIDAuthrGeneric1P4,
	)

	if result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("test = %#v, want configuration error", result.Tests[0])
	}
}

type scriptedDevice struct {
	t        *testing.T
	infos    [][]byte
	infoCall int
	commands []byte
}

func newScriptedDevice(t *testing.T, infos []protocol.AuthenticatorGetInfoResponse) *scriptedDevice {
	t.Helper()

	encoded := make([][]byte, len(infos))
	for index, info := range infos {
		encoded[index] = encodeCBOR(t, info)
	}

	return &scriptedDevice{t: t, infos: encoded}
}

func (d *scriptedDevice) CBOR(_ context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if len(data) == 0 {
		d.t.Fatal("empty CTAP command")
	}

	command := data[0]
	d.commands = append(d.commands, command)
	switch protocol.Command(command) {
	case protocol.AuthenticatorGetInfo:
		if d.infoCall >= len(d.infos) {
			d.t.Fatalf("unexpected GetInfo call %d", d.infoCall+1)
		}
		response := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       d.infos[d.infoCall],
		}
		d.infoCall++

		return response, nil
	case protocol.AuthenticatorReset:
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	default:
		return ctaptransport.CBORResponse{}, fmt.Errorf("unexpected command %#x", command)
	}
}

func runSingleAuthenticatorTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config ctap23.Config,
	testID conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), suiteWithTest(t, config, testID))
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func encryptGetInfoMember(
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

func iv(value byte) [aes.BlockSize]byte {
	var initializationVector [aes.BlockSize]byte
	for index := range initializationVector {
		initializationVector[index] = value
	}

	return initializationVector
}
