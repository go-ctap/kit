package authenticator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/ctap/yubico"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
)

func TestLoggingTransportRedactsClientPINSecrets(t *testing.T) {
	const (
		authParam = "sentinel-auth-param-550902"
		newPINEnc = "sentinel-new-pin-encrypted-849102"
		pinHash   = "sentinel-pin-hash-726411"
		token     = "sentinel-token-908123"
	)
	request := protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.PinUvAuthProtocolOne,
		SubCommand:        protocol.ClientPINSubCommandChangePIN,
		PinUvAuthParam:    []byte(authParam),
		NewPinEnc:         []byte(newPINEnc),
		PinHashEnc:        []byte(pinHash),
	}
	response := protocol.AuthenticatorClientPINResponse{PinUvAuthToken: []byte(token)}

	recorder := &recordingLogRecorder{}
	transport := newTestLoggingTransport(t, recorder, encodeCBOR(t, response))
	ctx := kitlog.WithCorrelation(t.Context(), "session-1", "operation-1", model.OperationChangePIN)
	if _, err := transport.CBOR(ctx, commandBytes(t, protocol.AuthenticatorClientPIN, request)); err != nil {
		t.Fatalf("CBOR: %v", err)
	}

	entries := recorder.entries
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one completed entry", entries)
	}
	completed := entries[0]
	if completed.SessionID != "session-1" || completed.OperationID != "operation-1" ||
		completed.SubCommandCode == nil || *completed.SubCommandCode != uint64(request.SubCommand) {
		t.Fatalf("completed correlation = %#v", completed)
	}
	assertLogHasNoSecrets(t, entries, authParam, newPINEnc, pinHash, token)
	assertRedactedFields(t, completed,
		"request.pinUvAuthParam", "request.newPinEnc", "request.pinHashEnc", "response.pinUvAuthToken")
}

func TestLoggingTransportRedactsLargeBlobCiphertext(t *testing.T) {
	const (
		requestCiphertext  = "sentinel-large-blob-request-190282"
		responseCiphertext = "sentinel-large-blob-response-7182"
	)
	request := protocol.AuthenticatorLargeBlobsRequest{
		Set:    []byte(requestCiphertext),
		Offset: 0,
	}
	response := protocol.AuthenticatorLargeBlobsResponse{Config: []byte(responseCiphertext)}

	recorder := &recordingLogRecorder{}
	transport := newTestLoggingTransport(t, recorder, encodeCBOR(t, response))
	if _, err := transport.CBOR(t.Context(), commandBytes(t, protocol.AuthenticatorLargeBlobs, request)); err != nil {
		t.Fatalf("CBOR: %v", err)
	}

	assertLogHasNoSecrets(t, recorder.entries, requestCiphertext, responseCiphertext)
	assertRedactedFields(t, recorder.entries[0], "request.set", "response.config")
}

func TestLoggingTransportUsesActualIteratorSubcommands(t *testing.T) {
	recorder := &recordingLogRecorder{}
	transport := newTestLoggingTransport(t, recorder, nil, nil)
	requests := []protocol.AuthenticatorCredentialManagementRequest{
		{SubCommand: protocol.CredentialManagementSubCommandEnumerateRPsBegin},
		{SubCommand: protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP},
	}
	for _, request := range requests {
		if _, err := transport.CBOR(t.Context(), commandBytes(t, protocol.AuthenticatorCredentialManagement, request)); err != nil {
			t.Fatalf("CBOR(%s): %v", request.SubCommand, err)
		}
	}

	completed := recorder.completed()
	if len(completed) != 2 {
		t.Fatalf("completed entries = %d, want 2", len(completed))
	}
	for index, entry := range completed {
		if entry.SubCommandCode == nil || *entry.SubCommandCode != uint64(requests[index].SubCommand) {
			t.Fatalf("entry %d subcommand = %#v", index, entry.SubCommandCode)
		}
	}
}

func TestLoggingTransportDistinguishesGetNextAssertion(t *testing.T) {
	recorder := &recordingLogRecorder{}
	transport := newTestLoggingTransport(t, recorder, nil, nil)
	if _, err := transport.CBOR(t.Context(), commandBytes(t, protocol.AuthenticatorGetAssertion, protocol.AuthenticatorGetAssertionRequest{RPID: "example.com"})); err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}
	if _, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetNextAssertion)}); err != nil {
		t.Fatalf("GetNextAssertion: %v", err)
	}

	completed := recorder.completed()
	if len(completed) != 2 ||
		completed[0].CommandCode != uint8(protocol.AuthenticatorGetAssertion) ||
		completed[1].CommandCode != uint8(protocol.AuthenticatorGetNextAssertion) {
		t.Fatalf("iterator commands = %#v", completed)
	}
}

func TestLoggingTransportRecordsCancellationWithoutChangingError(t *testing.T) {
	recorder := &recordingLogRecorder{}
	transport := newTestLoggingTransportWithErrors(t, recorder, []error{context.Canceled})
	_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorReset)})
	if err != context.Canceled {
		t.Fatalf("CBOR error = %v, want original context.Canceled", err)
	}

	completed := recorder.completed()
	if len(completed) != 1 || completed[0].Outcome != model.LogOutcomeCanceled {
		t.Fatalf("completed entries = %#v", completed)
	}
}

func TestLoggingTransportPreservesCTAPHIDCapabilities(t *testing.T) {
	base := &fakeCTAPTransport{
		vendorResponse: ctaphid.VendorResponse{Data: []byte{1, 2, 3}},
	}
	transport := newLoggingTransport(base, nil, testDecoder(t))
	if transport != base {
		t.Fatalf("transport = %T, want original transport without recorder", transport)
	}

	vendor, ok := transport.(yubico.VendorTransport)
	if !ok {
		t.Fatalf("logging transport %T does not preserve VendorTransport", transport)
	}
	response, err := vendor.Vendor(t.Context(), yubico.CommandGetDeviceInfo, nil)
	if err != nil {
		t.Fatalf("Vendor: %v", err)
	}
	if !slices.Equal(response.Data, base.vendorResponse.Data) || base.vendorCalls != 1 {
		t.Fatalf("vendor response = %#v, calls = %d", response, base.vendorCalls)
	}

	if err := transport.Cancel(t.Context()); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if base.cancelCalls != 1 {
		t.Fatalf("cancel calls = %d, want 1", base.cancelCalls)
	}
}

func newTestLoggingTransport(t *testing.T, recorder kitlog.Recorder, responses ...[]byte) ctapTransport {
	t.Helper()
	return newLoggingTransport(&fakeCTAPTransport{responses: responses}, recorder, testDecoder(t))
}

func newTestLoggingTransportWithErrors(t *testing.T, recorder kitlog.Recorder, errors []error) ctapTransport {
	t.Helper()
	return newLoggingTransport(&fakeCTAPTransport{errors: errors}, recorder, testDecoder(t))
}

func commandBytes(t *testing.T, command protocol.Command, request any) []byte {
	t.Helper()
	return slices.Concat([]byte{byte(command)}, encodeCBOR(t, request))
}

func encodeCBOR(t *testing.T, value any) []byte {
	t.Helper()
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("EncMode: %v", err)
	}
	encoded, err := encoder.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T): %v", value, err)
	}

	return encoded
}

func testDecoder(t *testing.T) cbor.DecMode {
	t.Helper()
	decoder, err := cbor.DecOptions{UTF8: cbor.UTF8DecodeInvalid}.DecMode()
	if err != nil {
		t.Fatalf("DecMode: %v", err)
	}

	return decoder
}

func assertLogHasNoSecrets(t *testing.T, entries []model.LogEntry, secrets ...string) {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("Marshal entries: %v", err)
	}
	for _, secret := range secrets {
		for _, encoded := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret))} {
			if len(encoded) > 0 && strings.Contains(string(raw), encoded) {
				t.Fatalf("log contains secret %q: %s", encoded, raw)
			}
		}
	}
}

func assertRedactedFields(t *testing.T, entry model.LogEntry, fields ...string) {
	t.Helper()
	for _, expected := range fields {
		found := false
		for _, field := range entry.RedactedFields {
			if field == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("redactedFields = %v, missing %q", entry.RedactedFields, expected)
		}
	}
}

type fakeCTAPTransport struct {
	responses      [][]byte
	errors         []error
	vendorResponse ctaphid.VendorResponse
	calls          int
	vendorCalls    int
	cancelCalls    int
}

func (t *fakeCTAPTransport) CBOR(context.Context, []byte) (ctaptransport.CBORResponse, error) {
	index := t.calls
	t.calls++
	if index < len(t.errors) && t.errors[index] != nil {
		return ctaptransport.CBORResponse{}, t.errors[index]
	}
	if index < len(t.responses) {
		return ctaptransport.CBORResponse{Data: t.responses[index]}, nil
	}
	return ctaptransport.CBORResponse{}, nil
}

func (*fakeCTAPTransport) Close() error                                 { return nil }
func (*fakeCTAPTransport) Ping(context.Context, []byte) ([]byte, error) { return nil, nil }
func (*fakeCTAPTransport) Wink(context.Context) error                   { return nil }
func (*fakeCTAPTransport) Lock(context.Context, uint8) error            { return nil }

func (t *fakeCTAPTransport) Cancel(context.Context) error {
	t.cancelCalls++
	return nil
}

func (t *fakeCTAPTransport) Vendor(
	context.Context,
	ctaphid.Command,
	[]byte,
) (ctaphid.VendorResponse, error) {
	t.vendorCalls++
	return t.vendorResponse, nil
}

type recordingLogRecorder struct {
	entries []model.LogEntry
}

func (s *recordingLogRecorder) Append(entry model.LogEntry) {
	s.entries = append(s.entries, entry)
}

func (s *recordingLogRecorder) completed() []model.LogEntry {
	return slices.Clone(s.entries)
}
