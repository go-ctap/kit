package config

func ResetResultForDevice(fingerprint string) ResetResult {
	return ResetResult{DeviceFingerprint: fingerprint, Reset: true}
}

func PINSetResult(fingerprint string) PINMutationResult {
	return PINMutationResult{Operation: PINMutationSet, DeviceFingerprint: fingerprint, PINState: StateConfigured}
}

func PINChangeResult(fingerprint string) PINMutationResult {
	return PINMutationResult{Operation: PINMutationChange, DeviceFingerprint: fingerprint, PINState: StateConfigured}
}

func AlwaysUVResult(fingerprint string, target AlwaysUVTarget, requestedAlwaysUV bool) AuthenticatorConfigResult {
	state := StateNotConfigured
	if requestedAlwaysUV {
		state = StateConfigured
	}

	return AuthenticatorConfigResult{
		Operation:         AuthenticatorConfigAlwaysUV,
		DeviceFingerprint: fingerprint,
		Target:            target,
		State:             state,
	}
}

func MinPINLengthResult(fingerprint string, operation SetMinPINLengthOperation) AuthenticatorConfigResult {
	return AuthenticatorConfigResult{
		Operation:           AuthenticatorConfigMinPINLength,
		DeviceFingerprint:   fingerprint,
		NewMinPINLength:     operation.NewMinPINLength,
		MinPINLengthRPIDs:   operation.MinPINLengthRPIDs,
		ForceChangePIN:      operation.ForceChangePIN,
		PINComplexityPolicy: operation.PINComplexityPolicy,
		State:               StateSupported,
	}
}

func LongTouchForResetResult(fingerprint string) AuthenticatorConfigResult {
	return AuthenticatorConfigResult{
		Operation:         AuthenticatorConfigLongTouch,
		DeviceFingerprint: fingerprint,
		State:             StateConfigured,
	}
}
