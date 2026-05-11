package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/kit/model/report"
)

func TestBuildStatusReportMatchesCtaphidOptionSemantics(t *testing.T) {
	info := ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionClientPIN:           false,
			ctaptypes.OptionUserVerification:    false,
			ctaptypes.OptionBioEnroll:           false,
			ctaptypes.OptionUvBioEnroll:         false,
			ctaptypes.OptionAuthenticatorConfig: true,
			ctaptypes.OptionUvAcfg:              false,
			ctaptypes.OptionAlwaysUv:            false,
			ctaptypes.OptionSetMinPINLength:     false,
		},
		LongTouchForReset: new(false),
	}

	r := BuildStatusReport(nilDevice(), info)

	if !r.PIN.Supported || r.PIN.Configured == nil || *r.PIN.Configured {
		t.Fatalf("clientPin false should mean supported but not configured: %#v", r.PIN)
	}

	if !r.UV.Supported || r.UV.Configured == nil || *r.UV.Configured {
		t.Fatalf("uv false should mean supported but not configured: %#v", r.UV)
	}

	if !r.Bio.Supported ||
		r.Bio.Configured == nil ||
		*r.Bio.Configured ||
		r.Bio.State != StateNotConfigured {
		t.Fatalf("bioEnroll false should mean supported but no enrollment provisioned: %#v", r.Bio)
	}

	if r.Bio.UVBioEnroll.Supported || r.Bio.UVBioEnroll.State != StateUnsupported {
		t.Fatalf("uvBioEnroll false should mean unsupported binding: %#v", r.Bio.UVBioEnroll)
	}

	if !r.AuthenticatorConfig.Supported || r.AuthenticatorConfig.State != StateSupported {
		t.Fatalf("authnrCfg true should mean supported: %#v", r.AuthenticatorConfig)
	}

	if r.AuthenticatorConfig.UVAcfg.Supported ||
		r.AuthenticatorConfig.UVAcfg.State != StateUnsupported {
		t.Fatalf("uvAcfg false should mean unsupported binding: %#v", r.AuthenticatorConfig.UVAcfg)
	}

	if !r.AuthenticatorConfig.AlwaysUV.Supported ||
		r.AuthenticatorConfig.AlwaysUV.Configured == nil ||
		*r.AuthenticatorConfig.AlwaysUV.Configured {
		t.Fatalf("alwaysUv false should mean supported but disabled: %#v", r.AuthenticatorConfig.AlwaysUV)
	}

	if r.AuthenticatorConfig.SetMinPINLength.Supported ||
		r.AuthenticatorConfig.SetMinPINLength.State != StateUnsupported {
		t.Fatalf("setMinPINLength false should mean unsupported: %#v", r.AuthenticatorConfig.SetMinPINLength)
	}

	if r.ResetHints.LongTouchForReset != StateNotConfigured {
		t.Fatalf("longTouchForReset false should mean supported but disabled: %#v", r.ResetHints.LongTouchForReset)
	}
}

func TestRetryStateReportsZeroRemainingRetries(t *testing.T) {
	powerCycle := false
	state := retryState(0, &powerCycle, nil)

	if state.State != StateSupported {
		t.Fatalf("state = %s, want supported", state.State)
	}

	if state.Remaining == nil || *state.Remaining != 0 {
		t.Fatalf("remaining retries = %#v, want explicit 0", state.Remaining)
	}

	if state.PowerCycleState == nil || *state.PowerCycleState {
		t.Fatalf("powerCycleState = %#v, want explicit false", state.PowerCycleState)
	}
}

func TestBuildStatusReportLabelsUVModality(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), ctaptypes.AuthenticatorGetInfoResponse{
		UvModality: ptr(ctaptypes.UserVerifyFingerprintInternal),
	})

	if statusReport.Bio.UVModality == nil || *statusReport.Bio.UVModality != uint(ctaptypes.UserVerifyFingerprintInternal) {
		t.Fatalf("uv modality = %#v, want numeric fingerprint flag", statusReport.Bio.UVModality)
	}
	if statusReport.Bio.UVModalityLabel != "fingerprint_internal" {
		t.Fatalf("uv modality label = %q, want fingerprint_internal", statusReport.Bio.UVModalityLabel)
	}
}

func TestPreviewOnlyBioStatusReportsSupportWhenNoEnrollmentProvisioned(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), ctaptypes.AuthenticatorGetInfoResponse{
		Versions: []ctaptypes.Version{ctaptypes.FIDO_2_0, ctaptypes.FIDO_2_1_PRE},
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionUserVerificationMgmtPreview: false,
		},
	})
	if !statusReport.Bio.Supported ||
		!statusReport.Bio.PreviewOnly ||
		statusReport.Bio.Configured == nil ||
		*statusReport.Bio.Configured ||
		statusReport.Bio.State != StatePreviewOnly {
		t.Fatalf("preview bio false should mean preview-only support with no enrollment provisioned: %#v", statusReport.Bio)
	}

	statusReport = BuildStatusReport(nilDevice(), ctaptypes.AuthenticatorGetInfoResponse{
		Versions: []ctaptypes.Version{ctaptypes.FIDO_2_0, ctaptypes.FIDO_2_1_PRE},
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionUserVerificationMgmtPreview: true,
		},
	})
	if !statusReport.Bio.Supported || statusReport.Bio.State != StatePreviewOnly {
		t.Fatalf("enabled preview bio option should be preview-only supported: %#v", statusReport.Bio)
	}
}

func TestBuildStatusReportPreservesExplicitZeroNullableLimits(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionClientPIN: false,
		},
		ForcePINChange:              ptr(false),
		MinPINLength:                ptr(uint(0)),
		MaxPINLength:                ptr(uint(0)),
		MaxRPIDsForSetMinPINLength:  ptr(uint(0)),
		PreferredPlatformUvAttempts: ptr(uint(0)),
		UvCountSinceLastPinEntry:    ptr(uint(0)),
		PinComplexityPolicy:         ptr(false),
	})

	if statusReport.PIN.MinPINLength == nil || *statusReport.PIN.MinPINLength != 0 {
		t.Fatalf("pin minPINLength = %#v, want explicit 0", statusReport.PIN.MinPINLength)
	}
	if statusReport.PIN.ForcePINChange == nil || *statusReport.PIN.ForcePINChange {
		t.Fatalf("forcePINChange = %#v, want explicit false", statusReport.PIN.ForcePINChange)
	}
	if statusReport.PIN.PinComplexityPolicy == nil || *statusReport.PIN.PinComplexityPolicy {
		t.Fatalf("pinComplexityPolicy = %#v, want explicit false", statusReport.PIN.PinComplexityPolicy)
	}
	if statusReport.Limits.MaxRPIDsForSetMinPINLength == nil || *statusReport.Limits.MaxRPIDsForSetMinPINLength != 0 {
		t.Fatalf("max RPIDs = %#v, want explicit 0", statusReport.Limits.MaxRPIDsForSetMinPINLength)
	}

	raw, err := json.Marshal(statusReport)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	text := string(raw)
	for _, want := range []string{
		`"minPINLength":0`,
		`"maxPINLength":0`,
		`"forcePINChange":false`,
		`"pinComplexityPolicy":false`,
		`"maxRPIDsForSetMinPINLength":0`,
		`"preferredPlatformUvAttempts":0`,
		`"uvCountSinceLastPinEntry":0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON missing %s: %s", want, text)
		}
	}
}

func TestBuildStatusReportOmitsAbsentNullableLimits(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), ctaptypes.AuthenticatorGetInfoResponse{})

	raw, err := json.Marshal(statusReport)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	text := string(raw)
	for _, reject := range []string{
		"minPINLength",
		"maxPINLength",
		"forcePINChange",
		"pinComplexityPolicy",
		"maxRPIDsForSetMinPINLength",
		"preferredPlatformUvAttempts",
		"uvCountSinceLastPinEntry",
	} {
		if strings.Contains(text, reject) {
			t.Fatalf("JSON included absent %s: %s", reject, text)
		}
	}
}

func nilDevice() report.DeviceReport {
	return report.DeviceReport{}
}

func ptr[T any](value T) *T {
	return &value
}
