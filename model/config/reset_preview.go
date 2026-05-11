package config

import "github.com/go-ctap/kit/model/safety"

const (
	warningResetFactoryDestructive   = "reset.factory.destructive"
	warningResetFactoryCredentials   = "reset.factory.credentials"
	warningResetFactoryPowerUpWindow = "reset.factory.power_up_window"
)

func BuildResetFactoryPreview(status StatusReport) ResetPreview {
	return ResetPreview{
		Device:     status.Device,
		ResetHints: status.ResetHints,
		Mode:       safety.PreviewModeExecute,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityDestructive,
				Code:     warningResetFactoryDestructive,
				Message:  "Factory reset permanently removes authenticator state and cannot be undone.",
			},
			{
				Severity: safety.SeverityDestructive,
				Code:     warningResetFactoryCredentials,
				Message:  "All resident credentials, PIN/UV configuration, biometric enrollments, and large-blob data on this authenticator may be erased.",
			},
			{
				Severity: safety.SeverityWarning,
				Code:     warningResetFactoryPowerUpWindow,
				Message:  "Factory reset must be requested shortly after authenticator power-up or reconnect; collect strong confirmation before reconnecting and run the confirmed reset promptly.",
			},
		},
	}
}

func BuildResetFactoryDryRunPreview(status StatusReport) ResetPreview {
	preview := BuildResetFactoryPreview(status)
	preview.Mode = safety.PreviewModeDryRun

	return preview
}
