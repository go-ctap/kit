package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) statusWithRetries(ctx context.Context) (appconfig.StatusReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.StatusReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseAuthenticatorCommand))
	}

	rep := appconfig.BuildStatusReport(r.env.Selected, r.env.Authenticator.GetInfo())
	if rep.PIN.Supported {
		retries, powerCycle, err := r.env.Authenticator.GetPINRetries(ctx)
		rep.PIN.Retries = retryState(
			retries,
			powerCycle,
			err,
			protocol.ClientPINSubCommandGetPINRetries,
		)
	}

	if rep.UV.Supported &&
		rep.UV.Configured != nil &&
		*rep.UV.Configured {
		retries, err := r.env.Authenticator.GetUVRetries(ctx)
		rep.UV.Retries = retryState(
			retries,
			nil,
			err,
			protocol.ClientPINSubCommandGetUVRetries,
		)
	}

	return rep, nil
}

func retryState(
	retries uint,
	powerCycle *bool,
	err error,
	subCommand protocol.ClientPINSubCommand,
) appconfig.RetryState {
	if err != nil {
		normalized := errornorm.Normalize(errornorm.Annotate(
			err,
			errornorm.WithClientPINSubCommand(failure.PhaseAuthenticatorCommand, subCommand),
		), "")

		return appconfig.RetryState{
			State:   appconfig.StateUnknown,
			Failure: failure.Snapshot(normalized),
		}
	}

	return appconfig.RetryState{
		State:           appconfig.StateSupported,
		Remaining:       new(retries),
		PowerCycleState: powerCycle,
	}
}
