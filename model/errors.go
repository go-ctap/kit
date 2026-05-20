package model

import (
	"errors"
	"strings"
)

type ErrorCategory string

const (
	ErrorUnsupported      ErrorCategory = "unsupported"
	ErrorPermissionDenied ErrorCategory = "permission-denied"
	ErrorTransportFailure ErrorCategory = "transport-failure"
	ErrorTimeout          ErrorCategory = "timeout"
	ErrorBusy             ErrorCategory = "busy"
	ErrorInvalidSession   ErrorCategory = "invalid-session"
	ErrorInvalidOperation ErrorCategory = "invalid-operation"
	ErrorInvalidState     ErrorCategory = "invalid-state"
	ErrorCanceled         ErrorCategory = "canceled"
)

type RuntimeError struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Err      error         `json:"err"`
}

func NewRuntimeError(category ErrorCategory, message string, err error) RuntimeError {
	return RuntimeError{Category: category, Message: message, Err: err}
}

func (e RuntimeError) Error() string {
	message := e.message()
	if strings.HasPrefix(message, "ctapkit: ") {
		return message
	}

	return "ctapkit: " + message
}

func (e RuntimeError) message() string {
	if e.Message != "" {
		return e.Message
	}

	if e.Err != nil {
		return e.Err.Error()
	}

	if e.Category != "" {
		return string(e.Category)
	}

	return "runtime error"
}

func (e RuntimeError) Unwrap() error {
	return e.Err
}

func IsErrorCategory(err error, category ErrorCategory) bool {
	var runtimeErr RuntimeError

	return errors.As(err, &runtimeErr) && runtimeErr.Category == category
}
