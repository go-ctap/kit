package service

import (
	"errors"

	"github.com/go-ctap/kit/model"
)

func runtimeErrorEnvelope(err error) *RuntimeErrorEnvelope {
	if err == nil {
		return nil
	}

	if runtimeErr, ok := errors.AsType[model.RuntimeError](err); ok {
		return &RuntimeErrorEnvelope{
			Category: runtimeErr.Category,
			Message:  runtimeErr.Error(),
		}
	}

	return &RuntimeErrorEnvelope{
		Message: err.Error(),
	}
}

func invalidSessionError() error {
	return model.NewRuntimeError(model.ErrorInvalidSession, "session not found", nil)
}

func invalidOperationError(message string) error {
	return model.NewRuntimeError(model.ErrorInvalidOperation, message, nil)
}
