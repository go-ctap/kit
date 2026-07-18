package service

import (
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model/failure"
)

func invalidSelectionError() error {
	return failure.New(failure.CodeSelectionInvalid, failure.WithPhase(failure.PhaseSelection))
}

func normalizeServicePhaseError(err error, phase failure.Phase) error {
	return errornorm.Normalize(errornorm.Annotate(err, errornorm.WithPhase(phase)), "")
}
