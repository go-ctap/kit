package config

import (
	"strconv"
	"strings"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/report"
	"github.com/samber/lo"
)

func BuildStatusReport(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) StatusReport {
	r := StatusReport{
		Device: device,
		PIN: PINStatus{
			State:   StateUnknown,
			Retries: RetryState{State: StateUnknown},
		},
		UV: UVStatus{
			State:   StateUnknown,
			Retries: RetryState{State: StateUnknown},
		},
		Bio: BioStatus{
			State:       StateUnknown,
			UVBioEnroll: CapabilityState{State: StateUnknown},
		},
		AuthenticatorConfig: AuthenticatorConfigStatus{
			State:           StateUnknown,
			UVAcfg:          CapabilityState{State: StateUnknown},
			AlwaysUV:        CapabilityState{State: StateUnknown},
			SetMinPINLength: CapabilityState{State: StateUnknown},
		},
		ResetHints: ResetHints{LongTouchForReset: StateUnknown},
	}

	r.PIN = buildPINStatus(info)
	r.UV = buildUVStatus(configuredOptionCapability(info, protocol.OptionUserVerification, false))
	r.Bio = buildBioStatus(bioCapability(info))
	if info.UvModality != nil {
		r.Bio.UVModality = new(uint(*info.UvModality))
		r.Bio.UVModalityLabel = formatUVModalityLabel(*info.UvModality)
	}
	r.ResetHints.LongTouchForReset = boolConfiguredState(info.LongTouchForReset)
	r.ResetHints.TransportsForReset = lo.Clone(info.TransportsForReset)
	r.Bio.UVBioEnroll = requiredOptionCapability(info, protocol.OptionUvBioEnroll, false)
	r.AuthenticatorConfig = buildAuthenticatorConfigStatus(requiredOptionCapability(info, protocol.OptionAuthenticatorConfig, false))
	r.AuthenticatorConfig.UVAcfg = requiredOptionCapability(info, protocol.OptionUvAcfg, false)
	r.AuthenticatorConfig.AlwaysUV = configuredOptionCapability(info, protocol.OptionAlwaysUv, false)
	r.AuthenticatorConfig.SetMinPINLength = requiredOptionCapability(info, protocol.OptionSetMinPINLength, false)
	r.Limits = buildLimitsStatus(info)

	return r
}

type uvModalityStringer interface {
	~uint
	String() string
}

func formatUVModalityLabel[T uvModalityStringer](modality T) string {
	if label := modality.String(); label != "" {
		return label
	}

	raw := uint(modality)
	if raw == 0 {
		return ""
	}

	labels := make([]string, 0)
	for bit := uint(1); bit != 0 && bit <= raw; bit <<= 1 {
		if raw&bit == 0 {
			continue
		}
		if label := T(bit).String(); label != "" {
			labels = append(labels, label)
			continue
		}
		labels = append(labels, "0x"+strings.ToUpper(strconv.FormatUint(uint64(bit), 16)))
	}

	return strings.Join(labels, ", ")
}

func buildPINStatus(info protocol.AuthenticatorGetInfoResponse) PINStatus {
	status := PINStatus{
		State:   StateUnknown,
		Retries: RetryState{State: StateUnknown},
	}
	status.ProtocolSupported = len(info.PinUvAuthProtocols) > 0
	status.ForcePINChange = info.ForcePINChange
	status.PinComplexityPolicy = info.PinComplexityPolicy
	status.PinComplexityURL = clonePtr(info.PinComplexityPolicyURL)
	status.MinPINLength = info.MinPINLength
	status.MaxPINLength = info.MaxPINLength

	value, ok := info.Options[protocol.OptionClientPIN]
	if !ok {
		status.State = StateUnsupported

		return status
	}

	status.Supported = true
	status.Configured = new(value)
	if value {
		status.State = StateConfigured
	} else {
		status.State = StateNotConfigured
	}

	return status
}

func configuredOptionCapability(info protocol.AuthenticatorGetInfoResponse, option protocol.Option, previewOnly bool) CapabilityState {
	value, ok := info.Options[option]
	if !ok {
		return CapabilityState{State: StateUnsupported}
	}

	state := CapabilityState{
		Supported:   true,
		Configured:  new(value),
		PreviewOnly: previewOnly,
	}
	if previewOnly {
		state.State = StatePreviewOnly
	} else if value {
		state.State = StateConfigured
	} else {
		state.State = StateNotConfigured
	}

	return state
}

func requiredOptionCapability(info protocol.AuthenticatorGetInfoResponse, option protocol.Option, previewOnly bool) CapabilityState {
	value, ok := info.Options[option]
	if !ok || !value {
		return CapabilityState{State: StateUnsupported}
	}

	state := CapabilityState{
		State:       StateSupported,
		Supported:   true,
		PreviewOnly: previewOnly,
	}
	if previewOnly {
		state.State = StatePreviewOnly
	}

	return state
}

func bioCapability(info protocol.AuthenticatorGetInfoResponse) CapabilityState {
	if info.Versions.IsPreviewOnly() {
		return configuredOptionCapability(info, protocol.OptionUserVerificationMgmtPreview, true)
	}

	return configuredOptionCapability(info, protocol.OptionBioEnroll, false)
}

func buildUVStatus(capability CapabilityState) UVStatus {
	return UVStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
		Retries:     RetryState{State: StateUnknown},
	}
}

func buildBioStatus(capability CapabilityState) BioStatus {
	return BioStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
		UVBioEnroll: CapabilityState{State: StateUnknown},
	}
}

func buildAuthenticatorConfigStatus(capability CapabilityState) AuthenticatorConfigStatus {
	return AuthenticatorConfigStatus{
		State:           capability.State,
		Supported:       capability.Supported,
		Configured:      capability.Configured,
		PreviewOnly:     capability.PreviewOnly,
		UVAcfg:          CapabilityState{State: StateUnknown},
		AlwaysUV:        CapabilityState{State: StateUnknown},
		SetMinPINLength: CapabilityState{State: StateUnknown},
	}
}

func boolConfiguredState(value *bool) StateValue {
	if value == nil {
		return StateUnknown
	}
	if *value {
		return StateConfigured
	}

	return StateNotConfigured
}

func buildLimitsStatus(info protocol.AuthenticatorGetInfoResponse) LimitsStatus {
	return LimitsStatus{
		MinPINLength:                info.MinPINLength,
		MaxPINLength:                info.MaxPINLength,
		MaxRPIDsForSetMinPINLength:  info.MaxRPIDsForSetMinPINLength,
		PreferredPlatformUVAttempts: info.PreferredPlatformUvAttempts,
		UVCountSinceLastPINEntry:    info.UvCountSinceLastPinEntry,
	}
}

func clonePtr[T any](value *T) *T {
	if value == nil {
		return nil
	}

	return new(*value)
}
