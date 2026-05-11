package config

func ResetResultForDevice(deviceID string) ResetResult {
	return ResetResult{DeviceID: deviceID, Reset: true}
}

func PINSetResult(deviceID string) PINMutationResult {
	return PINMutationResult{Operation: PINMutationSet, DeviceID: deviceID, PINState: StateConfigured}
}

func PINChangeResult(deviceID string) PINMutationResult {
	return PINMutationResult{Operation: PINMutationChange, DeviceID: deviceID, PINState: StateConfigured}
}

func AlwaysUVResult(deviceID string, target AlwaysUVTarget, requestedAlwaysUV bool) AuthenticatorConfigResult {
	state := StateNotConfigured
	if requestedAlwaysUV {
		state = StateConfigured
	}

	return AuthenticatorConfigResult{
		Operation: AuthenticatorConfigAlwaysUV,
		DeviceID:  deviceID,
		Target:    target,
		State:     state,
	}
}

func MinPINLengthResult(deviceID string, length uint) AuthenticatorConfigResult {
	return AuthenticatorConfigResult{
		Operation:       AuthenticatorConfigMinPINLength,
		DeviceID:        deviceID,
		NewMinPINLength: length,
		State:           StateSupported,
	}
}
