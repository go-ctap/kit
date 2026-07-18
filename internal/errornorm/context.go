package errornorm

import (
	"errors"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/failure"
)

type errorContext struct {
	phase      failure.Phase
	command    protocol.Command
	subCommand uint64
}

func WithPhase(phase failure.Phase) errorContext {
	return errorContext{phase: phase}
}

func WithCommand(phase failure.Phase, command protocol.Command) errorContext {
	return errorContext{
		phase:   phase,
		command: command,
	}
}

func WithClientPINSubCommand(phase failure.Phase, subCommand protocol.ClientPINSubCommand) errorContext {
	return withSubCommand(
		phase,
		protocol.AuthenticatorClientPIN,
		uint64(subCommand),
	)
}

func WithBioEnrollmentSubCommand(
	phase failure.Phase,
	command protocol.Command,
	subCommand protocol.BioEnrollmentSubCommand,
) errorContext {
	return withSubCommand(phase, command, uint64(subCommand))
}

func WithCredentialManagementSubCommand(
	phase failure.Phase,
	command protocol.Command,
	subCommand protocol.CredentialManagementSubCommand,
) errorContext {
	return withSubCommand(phase, command, uint64(subCommand))
}

func WithConfigSubCommand(phase failure.Phase, subCommand protocol.ConfigSubCommand) errorContext {
	return withSubCommand(
		phase,
		protocol.AuthenticatorConfig,
		uint64(subCommand),
	)
}

func withSubCommand(
	phase failure.Phase,
	command protocol.Command,
	subCommand uint64,
) errorContext {
	return errorContext{
		phase:      phase,
		command:    command,
		subCommand: subCommand,
	}
}

type annotatedError struct {
	err error
	ctx errorContext
}

func (e *annotatedError) Error() string {
	return e.err.Error()
}

func (e *annotatedError) Unwrap() error {
	return e.err
}

// Annotate records safe runtime context without changing the error identity.
// Context closest to the source wins over broader boundary context.
func Annotate(err error, ctx errorContext) error {
	if annotated, ok := errors.AsType[*annotatedError](err); ok {
		return annotated
	}

	return &annotatedError{err: err, ctx: ctx}
}
