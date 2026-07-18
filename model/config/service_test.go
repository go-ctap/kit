package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/report"
)

func TestBuildStatusReportMatchesCtaphidOptionSemantics(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN:           false,
			protocol.OptionUserVerification:    false,
			protocol.OptionBioEnroll:           false,
			protocol.OptionUvBioEnroll:         false,
			protocol.OptionAuthenticatorConfig: true,
			protocol.OptionUvAcfg:              false,
			protocol.OptionAlwaysUv:            false,
			protocol.OptionSetMinPINLength:     false,
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

func TestBuildStatusReportLabelsUVModality(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		UvModality: new(protocol.UserVerifyFingerprintInternal),
	})

	if statusReport.Bio.UVModality == nil || *statusReport.Bio.UVModality != uint(protocol.UserVerifyFingerprintInternal) {
		t.Fatalf("uv modality = %#v, want numeric fingerprint flag", statusReport.Bio.UVModality)
	}

	if statusReport.Bio.UVModalityLabel != "fingerprint_internal" {
		t.Fatalf("uv modality label = %q, want fingerprint_internal", statusReport.Bio.UVModalityLabel)
	}
}

func TestPreviewOnlyBioStatusReportsSupportWhenNoEnrollmentProvisioned(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Versions: []protocol.Version{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerificationMgmtPreview: false,
		},
	})
	if !statusReport.Bio.Supported ||
		!statusReport.Bio.PreviewOnly ||
		statusReport.Bio.Configured == nil ||
		*statusReport.Bio.Configured ||
		statusReport.Bio.State != StatePreviewOnly {
		t.Fatalf("preview bio false should mean preview-only support with no enrollment provisioned: %#v", statusReport.Bio)
	}

	statusReport = BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Versions: []protocol.Version{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerificationMgmtPreview: true,
		},
	})
	if !statusReport.Bio.Supported || statusReport.Bio.State != StatePreviewOnly {
		t.Fatalf("enabled preview bio option should be preview-only supported: %#v", statusReport.Bio)
	}
}

func TestBuildStatusReportAppliesEffectiveLimitsAndPreservesNullableZeros(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
		ForcePINChange:              false,
		MinPINLength:                0,
		MaxPINLength:                0,
		MaxRPIDsForSetMinPINLength:  new(uint(0)),
		PreferredPlatformUvAttempts: 0,
		UvCountSinceLastPinEntry:    new(uint(0)),
		PinComplexityPolicy:         new(false),
		PinComplexityPolicyURL:      []byte{},
	})

	if statusReport.PIN.MinPINLength != 4 {
		t.Fatalf("pin minPINLength = %#v, want effective 4", statusReport.PIN.MinPINLength)
	}

	if statusReport.PIN.MaxPINLength != 63 {
		t.Fatalf("pin maxPINLength = %#v, want effective 63", statusReport.PIN.MaxPINLength)
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
		`"minPINLength":4`,
		`"maxPINLength":63`,
		`"pinComplexityPolicy":false`,
		`"maxRPIDsForSetMinPINLength":0`,
		`"uvCountSinceLastPinEntry":0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON missing %s: %s", want, text)
		}
	}

	for _, reject := range []string{"forcePINChange", "pinComplexityPolicyURL", "preferredPlatformUvAttempts"} {
		if strings.Contains(text, reject) {
			t.Fatalf("JSON included zero-value %s: %s", reject, text)
		}
	}
}

func TestBuildStatusReportUsesEffectivePINLimitsAndOmitsOtherAbsentNullableLimits(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{})

	raw, err := json.Marshal(statusReport)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	text := string(raw)
	for _, reject := range []string{
		"forcePINChange",
		"pinComplexityPolicy",
		"pinComplexityPolicyURL",
		"maxRPIDsForSetMinPINLength",
		"preferredPlatformUvAttempts",
		"uvCountSinceLastPinEntry",
	} {
		if strings.Contains(text, reject) {
			t.Fatalf("JSON included absent %s: %s", reject, text)
		}
	}

	if !strings.Contains(text, `"maxPINLength":63`) {
		t.Fatalf("JSON omitted effective max PIN length: %s", text)
	}

	if !strings.Contains(text, `"minPINLength":4`) {
		t.Fatalf("JSON omitted effective minimum PIN length: %s", text)
	}
}

func nilDevice() report.DeviceReport {
	return report.DeviceReport{}
}
