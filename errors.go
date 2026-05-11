package ctapkit

import (
	"context"
	"errors"
	"io/fs"

	"github.com/go-ctap/kit/internal/ctaperrors"
	"github.com/go-ctap/kit/internal/device"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/transport"
)

func runtimeDeviceError(err error) error {
	switch {
	case errors.Is(err, device.ErrBusy):
		return model.NewRuntimeError(model.ErrorBusy, err.Error(), err)
	case errors.Is(err, device.ErrSelectionRequired):
		return model.NewRuntimeError(model.ErrorInvalidOperation, err.Error(), err)
	case errors.Is(err, device.ErrUnavailable):
		return model.NewRuntimeError(model.ErrorInvalidState, err.Error(), err)
	case errors.Is(err, transport.ErrPermissionDenied), errors.Is(err, fs.ErrPermission):
		return model.NewRuntimeError(model.ErrorPermissionDenied, err.Error(), err)
	case errors.Is(err, transport.ErrUnsupportedMode):
		return model.NewRuntimeError(model.ErrorUnsupported, err.Error(), err)
	case errors.Is(err, transport.ErrProxyUnavailable):
		return model.NewRuntimeError(model.ErrorTransportFailure, err.Error(), err)
	default:
		return err
	}
}

func normalizeRunError(err error) error {
	if err == nil {
		return nil
	}

	if model.IsErrorCategory(err, model.ErrorCanceled) {
		return err
	}

	if errors.Is(err, context.Canceled) {
		return model.NewRuntimeError(model.ErrorCanceled, "operation canceled", err)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return model.NewRuntimeError(model.ErrorCanceled, "operation canceled", err)
	}

	return ctaperrors.Normalize(err)
}

func runtimePINRequiredError(label string) error {
	return model.NewRuntimeError(model.ErrorInvalidOperation, label+" is required", appconfig.ErrPINRequired)
}
