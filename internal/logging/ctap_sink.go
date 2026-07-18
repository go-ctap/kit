package logging

import (
	"context"

	"github.com/go-ctap/ctap/diagnostic"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
)

func NewCTAPSink(logs Recorder) diagnostic.Sink {
	if logs == nil {
		return nil
	}

	return func(ctx context.Context, event diagnostic.Exchange) {
		selectionID, operationID, operationKind := Correlation(ctx)
		command, _ := event.Command.Name()
		entry := model.LogEntry{
			Timestamp:     event.StartedAt,
			Layer:         model.LogLayerCTAP,
			Code:          model.LogCodeCTAPCommand,
			OperationKind: operationKind,
			Command:       command,
			CommandCode:   uint8(event.Command),
			Request:       CBORDiagnosticPayload(event.Request),
			Response:      CBORDiagnosticPayload(event.Response),
			SelectionID:   selectionID,
			OperationID:   operationID,
		}
		setSubCommand(&entry, event.Command, event.SubCommand)
		entry.RedactedFields = appendPrefixedFields(entry.RedactedFields, event.Request.RedactedFields, "request")
		entry.RedactedFields = appendPrefixedFields(entry.RedactedFields, event.Response.RedactedFields, "response")

		logs.Append(FinishElapsed(entry, event.Duration, normalizedCommandError(event.Err, entry)))
	}
}

func setSubCommand(entry *model.LogEntry, command protocol.Command, code uint64) {
	if code == 0 {
		return
	}

	entry.SubCommandCode = &code
	switch command {
	case protocol.AuthenticatorClientPIN:
		entry.SubCommand, _ = protocol.ClientPINSubCommand(code).Name()
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		entry.SubCommand, _ = protocol.BioEnrollmentSubCommand(code).Name()
	case protocol.AuthenticatorCredentialManagement,
		protocol.PrototypeAuthenticatorCredentialManagement:
		entry.SubCommand, _ = protocol.CredentialManagementSubCommand(code).Name()
	case protocol.AuthenticatorConfig:
		entry.SubCommand, _ = protocol.ConfigSubCommand(code).Name()
	}
}

func appendPrefixedFields(destination, fields []string, prefix string) []string {
	for _, field := range fields {
		destination = append(destination, prefix+"."+field)
	}

	return destination
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
		switch protocol.Command(entry.CommandCode) {
		case protocol.AuthenticatorClientPIN:
			context = errornorm.WithClientPINSubCommand(phase, protocol.ClientPINSubCommand(*entry.SubCommandCode))
		case protocol.AuthenticatorCredentialManagement,
			protocol.PrototypeAuthenticatorCredentialManagement:
			context = errornorm.WithCredentialManagementSubCommand(
				phase,
				protocol.Command(entry.CommandCode),
				protocol.CredentialManagementSubCommand(*entry.SubCommandCode),
			)
		case protocol.AuthenticatorBioEnrollment,
			protocol.PrototypeAuthenticatorBioEnrollment:
			context = errornorm.WithBioEnrollmentSubCommand(
				phase,
				protocol.Command(entry.CommandCode),
				protocol.BioEnrollmentSubCommand(*entry.SubCommandCode),
			)
		case protocol.AuthenticatorConfig:
			context = errornorm.WithConfigSubCommand(phase, protocol.ConfigSubCommand(*entry.SubCommandCode))
		}
	}

	return errornorm.Normalize(errornorm.Annotate(err, context), string(entry.OperationKind))
}
