package config

import appconfig "github.com/go-ctap/kit/model/config"

func ResetResultForDevice(fingerprint string) appconfig.ResetResult {
	return appconfig.ResetResult{DeviceFingerprint: fingerprint, Reset: true}
}

func PINSetResult(fingerprint string) appconfig.PINMutationResult {
	return appconfig.PINMutationResult{Operation: appconfig.PINMutationSet, DeviceFingerprint: fingerprint, PINState: appconfig.StateConfigured}
}

func PINChangeResult(fingerprint string) appconfig.PINMutationResult {
	return appconfig.PINMutationResult{Operation: appconfig.PINMutationChange, DeviceFingerprint: fingerprint, PINState: appconfig.StateConfigured}
}

func AlwaysUVResult(fingerprint string, target appconfig.AlwaysUVTarget, requestedAlwaysUV bool) appconfig.AuthenticatorConfigResult {
	state := appconfig.StateNotConfigured
	if requestedAlwaysUV {
		state = appconfig.StateConfigured
	}

	return appconfig.AuthenticatorConfigResult{
		Operation:         appconfig.AuthenticatorConfigAlwaysUV,
		DeviceFingerprint: fingerprint,
		Target:            target,
		State:             state,
	}
}

func MinPINLengthResult(fingerprint string, operation appconfig.SetMinPINLengthOperation) appconfig.AuthenticatorConfigResult {
	return appconfig.AuthenticatorConfigResult{
		Operation:           appconfig.AuthenticatorConfigMinPINLength,
		DeviceFingerprint:   fingerprint,
		NewMinPINLength:     operation.NewMinPINLength,
		MinPINLengthRPIDs:   operation.MinPINLengthRPIDs,
		ForceChangePIN:      operation.ForceChangePIN,
		PINComplexityPolicy: operation.PINComplexityPolicy,
		State:               appconfig.StateSupported,
	}
}

func LongTouchForResetResult(fingerprint string) appconfig.AuthenticatorConfigResult {
	return appconfig.AuthenticatorConfigResult{
		Operation:         appconfig.AuthenticatorConfigLongTouch,
		DeviceFingerprint: fingerprint,
		State:             appconfig.StateConfigured,
	}
}
