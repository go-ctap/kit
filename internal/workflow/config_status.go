package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	rtconfig "github.com/go-ctap/kit/internal/config"
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

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.StatusReport{}, err
	}
	rep := rtconfig.BuildStatusReport(r.env.Selected, info)
	if rep.PIN.Supported {
		retries, powerCycle, err := device.GetPINRetries(ctx)
		if err != nil {
			rep.PIN.Retries = failedRetryState(err, protocol.ClientPINSubCommandGetPINRetries)
		} else {
			rep.PIN.Retries = appconfig.RetryState{
				State:           appconfig.StateSupported,
				Remaining:       new(retries),
				PowerCycleState: powerCycle,
			}
		}
	}

	if rep.UV.Supported &&
		rep.UV.Configured != nil &&
		*rep.UV.Configured {
		retries, err := device.GetUVRetries(ctx)
		if err != nil {
			rep.UV.Retries = failedRetryState(err, protocol.ClientPINSubCommandGetUVRetries)
		} else {
			rep.UV.Retries = appconfig.RetryState{
				State:     appconfig.StateSupported,
				Remaining: new(retries),
			}
		}
	}

	return rep, nil
}

func failedRetryState(
	err error,
	subCommand protocol.ClientPINSubCommand,
) appconfig.RetryState {
	normalized := errornorm.Normalize(errornorm.Annotate(
		err,
		errornorm.WithClientPINSubCommand(failure.PhaseAuthenticatorCommand, subCommand),
	), "")

	return appconfig.RetryState{
		State:   appconfig.StateUnknown,
		Failure: failure.Snapshot(normalized),
	}
}
