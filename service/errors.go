package service

import (
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model/failure"
)

func invalidSessionError() error {
	return failure.New(failure.CodeSessionInvalid, failure.WithPhase(failure.PhaseSession))
}

func normalizeServicePhaseError(err error, phase failure.Phase) error {
	return errornorm.Normalize(errornorm.Annotate(err, errornorm.WithPhase(phase)), "")
}
