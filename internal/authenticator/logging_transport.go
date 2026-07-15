package authenticator

import (
	"context"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/ctap/yubico"
	"github.com/go-ctap/kit/internal/errornorm"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

type ctapTransport interface {
	ctaptransport.Device
	yubico.VendorTransport
	Ping(context.Context, []byte) ([]byte, error)
	Wink(context.Context) error
	Lock(context.Context, uint8) error
	Cancel(context.Context) error
}

type loggingTransport struct {
	transport ctapTransport
	logs      kitlog.Recorder
	decoder   cbor.DecMode
}

func newLoggingTransport(transport ctapTransport, logs kitlog.Recorder, decoder cbor.DecMode) ctapTransport {
	if logs == nil {
		return transport
	}

	return &loggingTransport{transport: transport, logs: logs, decoder: decoder}
}

func (t *loggingTransport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	started := time.Now()
	decoded := decodeCommandRequest(t.decoder, data)
	response, err := t.transport.CBOR(ctx, data)
	t.appendCommand(ctx, started, decoded, decodeCommandResponse(t.decoder, decoded.spec.command, response.Data), err)

	return response, err
}

func (t *loggingTransport) Close() error {
	return t.transport.Close()
}

func (t *loggingTransport) Ping(ctx context.Context, data []byte) ([]byte, error) {
	return t.transport.Ping(ctx, data)
}

func (t *loggingTransport) Wink(ctx context.Context) error {
	return t.transport.Wink(ctx)
}

func (t *loggingTransport) Lock(ctx context.Context, seconds uint8) error {
	return t.transport.Lock(ctx, seconds)
}

func (t *loggingTransport) Cancel(ctx context.Context) error {
	return t.transport.Cancel(ctx)
}

func (t *loggingTransport) Vendor(
	ctx context.Context,
	command ctaphid.Command,
	data []byte,
) (ctaphid.VendorResponse, error) {
	return t.transport.Vendor(ctx, command, data)
}

type commandSpec struct {
	command          protocol.Command
	subCommandFamily string
	subCommand       string
	subCommandCode   *uint64
}

type decodedCommand struct {
	spec  commandSpec
	value kitlog.SafeJSONValue
}

func decodeCommandRequest(decoder cbor.DecMode, data []byte) decodedCommand {
	if len(data) == 0 {
		return decodedCommand{value: kitlog.SafeValue(struct{}{})}
	}

	command := protocol.Command(data[0])
	body := data[1:]
	decoded := decodedCommand{
		spec:  commandSpec{command: command},
		value: kitlog.SafeValue(struct{}{}),
	}

	switch command {
	case protocol.AuthenticatorMakeCredential:
		decoded.value = decodeSafe[protocol.AuthenticatorMakeCredentialRequest](decoder, body)
	case protocol.AuthenticatorGetAssertion:
		decoded.value = decodeSafe[protocol.AuthenticatorGetAssertionRequest](decoder, body)
	case protocol.AuthenticatorClientPIN:
		request, ok := decodeCBOR[protocol.AuthenticatorClientPINRequest](decoder, body)
		if ok {
			decoded.spec = clientPINCommand(request.SubCommand)
			decoded.value = kitlog.SafeValue(request)
		}
	case protocol.AuthenticatorCredentialManagement, protocol.PrototypeAuthenticatorCredentialManagement:
		request, ok := decodeCBOR[protocol.AuthenticatorCredentialManagementRequest](decoder, body)
		if ok {
			decoded.spec = commandWithSubcommand(command, "credentialManagement", uint64(request.SubCommand), request.SubCommand.Name)
			decoded.value = kitlog.SafeValue(request)
		}
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		request, ok := decodeCBOR[protocol.AuthenticatorBioEnrollmentRequest](decoder, body)
		if ok {
			decoded.spec = commandWithSubcommand(command, "bioEnrollment", uint64(request.SubCommand), request.SubCommand.Name)
			decoded.value = kitlog.SafeValue(request)
		}
	case protocol.AuthenticatorLargeBlobs:
		decoded.value = decodeSafe[protocol.AuthenticatorLargeBlobsRequest](decoder, body)
	case protocol.AuthenticatorConfig:
		request, ok := decodeCBOR[protocol.AuthenticatorConfigRequest](decoder, body)
		if ok {
			decoded.spec = commandWithSubcommand(command, "config", uint64(request.SubCommand), request.SubCommand.Name)
			decoded.value = kitlog.SafeValue(request)
		}
	}

	return decoded
}

func decodeCommandResponse(decoder cbor.DecMode, command protocol.Command, data []byte) kitlog.SafeJSONValue {
	if len(data) == 0 {
		return kitlog.SafeValue(struct{}{})
	}

	switch command {
	case protocol.AuthenticatorMakeCredential:
		return decodeSafe[protocol.AuthenticatorMakeCredentialResponse](decoder, data)
	case protocol.AuthenticatorGetAssertion, protocol.AuthenticatorGetNextAssertion:
		return decodeSafe[protocol.AuthenticatorGetAssertionResponse](decoder, data)
	case protocol.AuthenticatorGetInfo:
		return decodeSafe[protocol.AuthenticatorGetInfoResponse](decoder, data)
	case protocol.AuthenticatorClientPIN:
		return decodeSafe[protocol.AuthenticatorClientPINResponse](decoder, data)
	case protocol.AuthenticatorCredentialManagement, protocol.PrototypeAuthenticatorCredentialManagement:
		return decodeSafe[protocol.AuthenticatorCredentialManagementResponse](decoder, data)
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		return decodeSafe[protocol.AuthenticatorBioEnrollmentResponse](decoder, data)
	case protocol.AuthenticatorLargeBlobs:
		return decodeSafe[protocol.AuthenticatorLargeBlobsResponse](decoder, data)
	default:
		return kitlog.SafeValue(struct{}{})
	}
}

func decodeSafe[T any](decoder cbor.DecMode, data []byte) kitlog.SafeJSONValue {
	value, ok := decodeCBOR[T](decoder, data)
	if !ok {
		return kitlog.SafeJSONValue{}
	}

	return kitlog.SafeValue(value)
}

func decodeCBOR[T any](decoder cbor.DecMode, data []byte) (T, bool) {
	var value T
	if err := decoder.Unmarshal(data, &value); err != nil {
		return value, false
	}

	return value, true
}

type subcommandNamer func() (string, bool)

func commandWithSubcommand(command protocol.Command, family string, code uint64, name subcommandNamer) commandSpec {
	label, _ := name()

	return commandSpec{
		command:          command,
		subCommandFamily: family,
		subCommand:       label,
		subCommandCode:   &code,
	}
}

func clientPINCommand(value protocol.ClientPINSubCommand) commandSpec {
	return commandWithSubcommand(protocol.AuthenticatorClientPIN, "clientPIN", uint64(value), value.Name)
}

func (t *loggingTransport) appendCommand(
	ctx context.Context,
	started time.Time,
	decoded decodedCommand,
	response kitlog.SafeJSONValue,
	err error,
) {
	if t.logs == nil {
		return
	}

	sessionID, operationID, operationKind := kitlog.Correlation(ctx)
	commandName, _ := decoded.spec.command.Name()
	entry := model.LogEntry{
		Timestamp:        started.UTC(),
		Layer:            model.LogLayerCTAP,
		Code:             model.LogCodeCTAPCommand,
		OperationKind:    operationKind,
		Command:          commandName,
		CommandCode:      uint8(decoded.spec.command),
		SubCommandFamily: decoded.spec.subCommandFamily,
		SubCommand:       decoded.spec.subCommand,
		SubCommandCode:   decoded.spec.subCommandCode,
		Request:          kitlog.Payload(decoded.value),
		RedactedFields:   prefixFields(decoded.value.RedactedFields, "request"),
		SessionID:        sessionID,
		OperationID:      operationID,
	}
	entry.Response = kitlog.Payload(response)
	entry.RedactedFields = slices.Concat(entry.RedactedFields, prefixFields(response.RedactedFields, "response"))
	t.logs.Append(kitlog.Finish(entry, started, normalizedCommandError(err, entry)))
}

func normalizedCommandError(err error, entry model.LogEntry) error {
	if err == nil {
		return nil
	}

	phase := failure.PhaseAuthenticatorCommand
	if entry.CommandCode == uint8(protocol.AuthenticatorGetNextAssertion) {
		phase = failure.PhaseAssertionContinuation
	}
	context := errornorm.WithCommand(phase, protocol.Command(entry.CommandCode))
	if entry.SubCommandCode != nil {
		switch entry.SubCommandFamily {
		case "clientPIN":
			context = errornorm.WithClientPINSubCommand(phase, protocol.ClientPINSubCommand(*entry.SubCommandCode))
		case "credentialManagement":
			context = errornorm.WithCredentialManagementSubCommand(
				phase,
				protocol.Command(entry.CommandCode),
				protocol.CredentialManagementSubCommand(*entry.SubCommandCode),
			)
		case "bioEnrollment":
			context = errornorm.WithBioEnrollmentSubCommand(
				phase,
				protocol.Command(entry.CommandCode),
				protocol.BioEnrollmentSubCommand(*entry.SubCommandCode),
			)
		case "config":
			context = errornorm.WithConfigSubCommand(phase, protocol.ConfigSubCommand(*entry.SubCommandCode))
		}
	}

	return errornorm.Normalize(errornorm.Annotate(err, context), string(entry.OperationKind))
}

func prefixFields(fields []string, prefix string) []string {
	prefixed := make([]string, 0, len(fields))
	for _, field := range fields {
		prefixed = append(prefixed, prefix+"."+field)
	}

	return prefixed
}
