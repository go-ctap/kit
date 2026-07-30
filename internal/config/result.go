package config

import (
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/report"
)

func ResetResultForDevice(attachmentID report.AttachmentID) appconfig.ResetResult {
	return appconfig.ResetResult{AttachmentID: attachmentID, Reset: true}
}

func PINSetResult(attachmentID report.AttachmentID) appconfig.PINMutationResult {
	return appconfig.PINMutationResult{Operation: appconfig.PINMutationSet, AttachmentID: attachmentID, PINState: appconfig.StateConfigured}
}

func PINChangeResult(attachmentID report.AttachmentID) appconfig.PINMutationResult {
	return appconfig.PINMutationResult{Operation: appconfig.PINMutationChange, AttachmentID: attachmentID, PINState: appconfig.StateConfigured}
}

func AlwaysUVResult(attachmentID report.AttachmentID, target appconfig.AlwaysUVTarget, requestedAlwaysUV bool) appconfig.AuthenticatorConfigResult {
	state := appconfig.StateNotConfigured
	if requestedAlwaysUV {
		state = appconfig.StateConfigured
	}

	return appconfig.AuthenticatorConfigResult{
		Operation:    appconfig.AuthenticatorConfigAlwaysUV,
		AttachmentID: attachmentID,
		Target:       target,
		State:        state,
	}
}

func EnterpriseAttestationResult(attachmentID report.AttachmentID) appconfig.AuthenticatorConfigResult {
	return appconfig.AuthenticatorConfigResult{
		Operation:    appconfig.AuthenticatorConfigEnterprise,
		AttachmentID: attachmentID,
		State:        appconfig.StateConfigured,
	}
}

func MinPINLengthResult(attachmentID report.AttachmentID, operation appconfig.SetMinPINLengthOperation) appconfig.AuthenticatorConfigResult {
	return appconfig.AuthenticatorConfigResult{
		Operation:           appconfig.AuthenticatorConfigMinPINLength,
		AttachmentID:        attachmentID,
		NewMinPINLength:     operation.NewMinPINLength,
		MinPINLengthRPIDs:   operation.MinPINLengthRPIDs,
		ForceChangePIN:      operation.ForceChangePIN,
		PINComplexityPolicy: operation.PINComplexityPolicy,
		State:               appconfig.StateSupported,
	}
}

func LongTouchForResetResult(attachmentID report.AttachmentID) appconfig.AuthenticatorConfigResult {
	return appconfig.AuthenticatorConfigResult{
		Operation:    appconfig.AuthenticatorConfigLongTouch,
		AttachmentID: attachmentID,
		State:        appconfig.StateConfigured,
	}
}
