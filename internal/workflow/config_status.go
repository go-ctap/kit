package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
)

func (r Runner) ConfigStatus(ctx context.Context, device ConfigStatusDevice) (appconfig.StatusReport, error) {
	return r.statusWithRetries(ctx, device)
}

func (r Runner) statusWithRetries(
	ctx context.Context,
	device ConfigStatusDevice,
) (appconfig.StatusReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.StatusReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseAuthenticatorCommand))
	}

	rep := appconfig.BuildStatusReport(r.env.Selected, device.GetInfo())
	if rep.PIN.Supported {
		retries, powerCycle, err := device.GetPINRetries(ctx)
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
		retries, err := device.GetUVRetries(ctx)
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
