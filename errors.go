package ctapkit

import (
	"errors"
	"io/fs"

	"github.com/go-ctap/kit/internal/device"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model/failure"
)

func normalizeLeaseError(err error) error {
	switch {
	case errors.Is(err, device.ErrBusy):
		return failure.Wrap(failure.CodeDeviceBusy, err, failure.WithPhase(failure.PhaseSession))
	case errors.Is(err, fs.ErrPermission):
		return failure.Wrap(
			failure.CodeTransportPermissionDenied,
			err,
			failure.WithPhase(failure.PhaseSession),
		)
	default:
		return normalizeBoundaryError(err, failure.PhaseSession)
	}
}

func normalizeRunError(err error, operation string) error {
	return errornorm.Normalize(errornorm.Annotate(
		err,
		errornorm.WithPhase(failure.PhaseSession),
	), operation)
}

func normalizeBoundaryError(err error, phase failure.Phase) error {
	return errornorm.Normalize(errornorm.Annotate(err, errornorm.WithPhase(phase)), "")
}

func runtimePINRequiredError(field string) error {
	return failure.New(failure.CodePINRequired,
		failure.WithPhase(failure.PhaseValidation),
		failure.WithParams(map[string]string{"field": field}),
	)
}
