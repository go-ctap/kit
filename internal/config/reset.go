package config

import (
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/safety"
)

const (
	warningResetFactoryDestructive   = "reset.factory.destructive"
	warningResetFactoryCredentials   = "reset.factory.credentials"
	warningResetFactoryPowerUpWindow = "reset.factory.power_up_window"
)

func BuildResetFactoryPreview(status appconfig.StatusReport) appconfig.ResetPreview {
	return appconfig.ResetPreview{
		Device:     status.Device,
		ResetHints: status.ResetHints,
		Mode:       safety.PreviewModeExecute,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityDestructive,
				Code:     warningResetFactoryDestructive,
				Message:  "Factory reset is destructive, invalidates authenticator credentials, and cannot be undone.",
			},
			{
				Severity: safety.SeverityDestructive,
				Code:     warningResetFactoryCredentials,
				Message:  "CTAP reset invalidates every generated credential, erases all discoverable credentials, and restores any serialized large-blob array to its initial empty value.",
			},
			{
				Severity: safety.SeverityWarning,
				Code:     warningResetFactoryPowerUpWindow,
				Message:  "CTAP 2.1 and later require a displayless authenticator to receive reset within 10 seconds of power-up; reconnect or power-cycle it immediately before execution when necessary.",
			},
		},
	}
}

func BuildResetFactoryDryRunPreview(status appconfig.StatusReport) appconfig.ResetPreview {
	preview := BuildResetFactoryPreview(status)
	preview.Mode = safety.PreviewModeDryRun

	return preview
}
