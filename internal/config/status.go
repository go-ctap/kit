package config

import (
	"slices"
	"strconv"
	"strings"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/report"
	"github.com/samber/lo"
)

func BuildStatusReport(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) appconfig.StatusReport {
	r := appconfig.StatusReport{
		Device: device,
		PIN: appconfig.PINStatus{
			State:   appconfig.StateUnknown,
			Retries: appconfig.RetryState{State: appconfig.StateUnknown},
		},
		UV: appconfig.UVStatus{
			State:   appconfig.StateUnknown,
			Retries: appconfig.RetryState{State: appconfig.StateUnknown},
		},
		Bio: appconfig.BioStatus{
			State:       appconfig.StateUnknown,
			UVBioEnroll: appconfig.CapabilityState{State: appconfig.StateUnknown},
		},
		AuthenticatorConfig: appconfig.AuthenticatorConfigStatus{
			State:             appconfig.StateUnknown,
			UVAcfg:            appconfig.CapabilityState{State: appconfig.StateUnknown},
			AlwaysUV:          appconfig.CapabilityState{State: appconfig.StateUnknown},
			SetMinPINLength:   appconfig.CapabilityState{State: appconfig.StateUnknown},
			LongTouchForReset: appconfig.CapabilityState{State: appconfig.StateUnknown},
		},
		ResetHints: appconfig.ResetHints{LongTouchForReset: appconfig.StateUnknown},
	}

	r.PIN = buildPINStatus(info)
	r.UV = buildUVStatus(configuredOptionCapability(info, protocol.OptionUserVerification, false))
	r.Bio = buildBioStatus(bioCapability(info))
	if info.UvModality != nil {
		r.Bio.UVModality = new(uint(*info.UvModality))
		r.Bio.UVModalityLabel = formatUVModalityLabel(*info.UvModality)
	}
	r.ResetHints.LongTouchForReset = boolConfiguredState(info.LongTouchForReset)
	r.ResetHints.TransportsForReset = lo.Map(info.TransportsForReset, func(value credential.AuthenticatorTransport, _ int) string {
		return string(value)
	})
	r.Bio.UVBioEnroll = requiredOptionCapability(info, protocol.OptionUvBioEnroll, false)
	r.AuthenticatorConfig = buildAuthenticatorConfigStatus(requiredOptionCapability(info, protocol.OptionAuthenticatorConfig, false))
	r.AuthenticatorConfig.UVAcfg = requiredOptionCapability(info, protocol.OptionUvAcfg, false)
	r.AuthenticatorConfig.AlwaysUV = configuredOptionCapability(info, protocol.OptionAlwaysUv, false)
	r.AuthenticatorConfig.SetMinPINLength = requiredOptionCapability(info, protocol.OptionSetMinPINLength, false)
	r.AuthenticatorConfig.LongTouchForReset = longTouchCapability(info)
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

func buildPINStatus(info protocol.AuthenticatorGetInfoResponse) appconfig.PINStatus {
	status := appconfig.PINStatus{
		State:   appconfig.StateUnknown,
		Retries: appconfig.RetryState{State: appconfig.StateUnknown},
	}
	status.ProtocolSupported = len(info.PinUvAuthProtocols) > 0
	status.ForcePINChange = info.ForcePINChange
	status.PinComplexityPolicy = info.PinComplexityPolicy
	status.PinComplexityURL = info.PinComplexityPolicyURLString()
	status.MinPINLength = info.EffectiveMinPINLength()
	status.MaxPINLength = info.EffectiveMaxPINLength()

	value, ok := info.Options[protocol.OptionClientPIN]
	if !ok {
		status.State = appconfig.StateUnsupported

		return status
	}

	status.Supported = true
	status.Configured = new(value)
	if value {
		status.State = appconfig.StateConfigured
	} else {
		status.State = appconfig.StateNotConfigured
	}

	return status
}

func configuredOptionCapability(info protocol.AuthenticatorGetInfoResponse, option protocol.Option, previewOnly bool) appconfig.CapabilityState {
	value, ok := info.Options[option]
	if !ok {
		return appconfig.CapabilityState{State: appconfig.StateUnsupported}
	}

	state := appconfig.CapabilityState{
		Supported:   true,
		Configured:  new(value),
		PreviewOnly: previewOnly,
	}

	if previewOnly {
		state.State = appconfig.StatePreviewOnly
	} else if value {
		state.State = appconfig.StateConfigured
	} else {
		state.State = appconfig.StateNotConfigured
	}

	return state
}

func requiredOptionCapability(info protocol.AuthenticatorGetInfoResponse, option protocol.Option, previewOnly bool) appconfig.CapabilityState {
	value, ok := info.Options[option]
	if !ok || !value {
		return appconfig.CapabilityState{State: appconfig.StateUnsupported}
	}

	state := appconfig.CapabilityState{
		State:       appconfig.StateSupported,
		Supported:   true,
		PreviewOnly: previewOnly,
	}

	if previewOnly {
		state.State = appconfig.StatePreviewOnly
	}

	return state
}

func bioCapability(info protocol.AuthenticatorGetInfoResponse) appconfig.CapabilityState {
	if info.Versions.IsPreviewOnly() {
		return configuredOptionCapability(info, protocol.OptionUserVerificationMgmtPreview, true)
	}

	return configuredOptionCapability(info, protocol.OptionBioEnroll, false)
}

func buildUVStatus(capability appconfig.CapabilityState) appconfig.UVStatus {
	return appconfig.UVStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
		Retries:     appconfig.RetryState{State: appconfig.StateUnknown},
	}
}

func buildBioStatus(capability appconfig.CapabilityState) appconfig.BioStatus {
	return appconfig.BioStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
		UVBioEnroll: appconfig.CapabilityState{State: appconfig.StateUnknown},
	}
}

func buildAuthenticatorConfigStatus(capability appconfig.CapabilityState) appconfig.AuthenticatorConfigStatus {
	return appconfig.AuthenticatorConfigStatus{
		State:             capability.State,
		Supported:         capability.Supported,
		Configured:        capability.Configured,
		PreviewOnly:       capability.PreviewOnly,
		UVAcfg:            appconfig.CapabilityState{State: appconfig.StateUnknown},
		AlwaysUV:          appconfig.CapabilityState{State: appconfig.StateUnknown},
		SetMinPINLength:   appconfig.CapabilityState{State: appconfig.StateUnknown},
		LongTouchForReset: appconfig.CapabilityState{State: appconfig.StateUnknown},
	}
}

func longTouchCapability(info protocol.AuthenticatorGetInfoResponse) appconfig.CapabilityState {
	if info.LongTouchForReset == nil ||
		!slices.Contains(info.AuthenticatorConfigCommands, protocol.ConfigSubCommandEnableLongTouchForReset) {
		return appconfig.CapabilityState{State: appconfig.StateUnsupported}
	}

	return appconfig.CapabilityState{
		State:      boolConfiguredState(info.LongTouchForReset),
		Supported:  true,
		Configured: info.LongTouchForReset,
	}
}

func boolConfiguredState(value *bool) appconfig.StateValue {
	if value == nil {
		return appconfig.StateUnknown
	}

	if *value {
		return appconfig.StateConfigured
	}

	return appconfig.StateNotConfigured
}

func buildLimitsStatus(info protocol.AuthenticatorGetInfoResponse) appconfig.LimitsStatus {
	return appconfig.LimitsStatus{
		MinPINLength:                info.EffectiveMinPINLength(),
		MaxPINLength:                info.EffectiveMaxPINLength(),
		MaxRPIDsForSetMinPINLength:  info.MaxRPIDsForSetMinPINLength,
		PreferredPlatformUVAttempts: info.PreferredPlatformUvAttempts,
		UVCountSinceLastPINEntry:    info.UvCountSinceLastPinEntry,
	}
}
