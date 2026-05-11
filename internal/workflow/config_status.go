package workflow

import (
	"context"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/report"
)

func (r Runner) configStatus(ctx context.Context) (appconfig.StatusReport, error) {
	if rep, ok := r.env.Cache.Config(); ok {
		return rep, nil
	}

	rep, err := r.statusWithRetries(ctx)
	if err != nil {
		return appconfig.StatusReport{}, err
	}

	r.env.Cache.SetConfig(rep)

	return rep, nil
}

func (r Runner) statusReport() appconfig.StatusReport {
	return buildStatusReport(r.env.Selected, r.infoProvider().GetInfo())
}

func buildStatusReport(selected report.DeviceReport, info ctaptypes.AuthenticatorGetInfoResponse) appconfig.StatusReport {
	return appconfig.BuildStatusReport(selected, info)
}

func (r Runner) statusWithRetries(ctx context.Context) (appconfig.StatusReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.StatusReport{}, err
	}

	authenticator := r.configManager()
	rep := r.statusReport()
	if rep.PIN.Supported {
		retries, powerCycle, err := authenticator.GetPINRetries()
		rep.PIN.Retries = retryState(retries, &powerCycle, err)
	}

	if rep.UV.Supported &&
		rep.UV.Configured != nil &&
		*rep.UV.Configured {
		retries, err := authenticator.GetUVRetries()
		rep.UV.Retries = retryState(retries, nil, err)
	}

	return rep, nil
}

func retryState(retries uint, powerCycle *bool, err error) appconfig.RetryState {
	if err != nil {
		return appconfig.RetryState{State: appconfig.StateUnknown, Error: err.Error()}
	}

	return appconfig.RetryState{
		State:           appconfig.StateSupported,
		Remaining:       new(retries),
		PowerCycleState: powerCycle,
	}
}
