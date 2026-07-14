package ctapkit

import (
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model/failure"
)

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
