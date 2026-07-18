package conformance_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/conformance"
	"github.com/go-ctap/kit/model/failure"
)

func TestEvaluateGetInfoAcceptsVersionSpecificProfiles(t *testing.T) {
	tests := []struct {
		name   string
		info   protocol.AuthenticatorGetInfoResponse
		target conformance.Target
	}{
		{
			name: "FIDO 2.1",
			info: validFIDO21Info(),
			target: conformance.Target{
				Specification: conformance.SpecificationCTAP21,
				Profile:       conformance.ProfileFIDO21,
			},
		},
		{
			name: "FIDO 2.3",
			info: validFIDO23Info(),
			target: conformance.Target{
				Specification: conformance.SpecificationCTAP23,
				Profile:       conformance.ProfileFIDO23,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := conformance.EvaluateGetInfo(test.info)
			if report.Target == nil || *report.Target != test.target {
				t.Fatalf("target = %#v, want %#v", report.Target, test.target)
			}
			assertNoAssessments(t, report)
		})
	}
}

func TestEvaluateGetInfoScreenshotRegressionIsProfileSpecific(t *testing.T) {
	info := validFIDO21Info()
	info.Options[protocol.OptionLargeBlobs] = true
	info.MaxSerializedLargeBlobArray = 1024

	report21 := conformance.EvaluateGetInfo(info)
	assertNoAssessments(t, report21)

	info.Versions = protocol.Versions{protocol.FIDO_2_3}
	report23 := conformance.EvaluateGetInfo(info)
	finding := requireOnlyFinding(t, report23, conformance.RuleSetMinPINSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x03"),
	})
	if hasExpectedValue(report23, "0x02") {
		t.Fatal("alwaysUv=false incorrectly required toggleAlwaysUv (0x02)")
	}
}

func TestEvaluateGetInfoResolvesProfilesIndependentlyOfVersionOrder(t *testing.T) {
	info := validFIDO23Info()
	info.Versions = protocol.Versions{
		protocol.FIDO_2_1,
		protocol.FIDO_2_0,
		protocol.FIDO_2_3,
		protocol.FIDO_2_1_PRE,
	}

	report := conformance.EvaluateGetInfo(info)
	if report.Target == nil || *report.Target != (conformance.Target{Specification: conformance.SpecificationCTAP23, Profile: conformance.ProfileFIDO23}) {
		t.Fatalf("target = %#v", report.Target)
	}
	wantAdvertised := []conformance.Profile{
		conformance.ProfileFIDO20,
		conformance.ProfileFIDO21Pre,
		conformance.ProfileFIDO21,
		conformance.ProfileFIDO23,
	}

	if !slices.Equal(report.AdvertisedProfiles, wantAdvertised) {
		t.Fatalf("advertised profiles = %#v, want %#v", report.AdvertisedProfiles, wantAdvertised)
	}
	assertNoAssessments(t, report)
}

func TestEvaluateGetInfoUsesStableTargetsAndLeavesOtherProfilesUnresolved(t *testing.T) {
	t.Run("preview does not outrank stable FIDO 2.0", func(t *testing.T) {
		report := conformance.EvaluateGetInfo(protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1_PRE, protocol.FIDO_2_0},
		})
		want := conformance.Target{Specification: conformance.SpecificationCTAP20, Profile: conformance.ProfileFIDO20}
		if report.Target == nil || *report.Target != want {
			t.Fatalf("target = %#v, want %#v", report.Target, want)
		}
	})

	tests := []struct {
		name       string
		versions   protocol.Versions
		advertised []conformance.Profile
	}{
		{name: "empty", versions: protocol.Versions{}, advertised: []conformance.Profile{}},
		{name: "preview only", versions: protocol.Versions{protocol.FIDO_2_1_PRE}, advertised: []conformance.Profile{conformance.ProfileFIDO21Pre}},
		{name: "U2F only", versions: protocol.Versions{protocol.U2F_V2}, advertised: []conformance.Profile{conformance.ProfileU2FV2}},
		{name: "unknown only", versions: protocol.Versions{protocol.Version("future")}, advertised: []conformance.Profile{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := conformance.EvaluateGetInfo(protocol.AuthenticatorGetInfoResponse{Versions: test.versions})
			if report.Target != nil {
				t.Fatalf("target = %#v, want unresolved", report.Target)
			}

			if !slices.Equal(report.AdvertisedProfiles, test.advertised) {
				t.Fatalf("advertised profiles = %#v, want %#v", report.AdvertisedProfiles, test.advertised)
			}
			assertNoAssessments(t, report)
		})
	}
}

func TestEvaluateGetInfoDoesNotPromoteFIDO22NoteToNormativeFinding(t *testing.T) {
	t.Run("identifier only remains unresolved", func(t *testing.T) {
		report := conformance.EvaluateGetInfo(protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.Version("FIDO_2_2")},
		})
		if report.Target != nil {
			t.Fatalf("target = %#v, want unresolved", report.Target)
		}
		assertNoAssessments(t, report)
	})

	for _, version := range []protocol.Version{protocol.FIDO_2_1, protocol.FIDO_2_3} {
		t.Run(string(version), func(t *testing.T) {
			info := validFIDO21Info()
			if version == protocol.FIDO_2_3 {
				info = validFIDO23Info()
			}
			info.Versions = append(info.Versions, protocol.Version("FIDO_2_2"))
			assertNoAssessments(t, conformance.EvaluateGetInfo(info))
		})
	}
}

func TestEvaluateGetInfoSeparatesFIDO21AndFIDO23RKSemantics(t *testing.T) {
	info21 := validFIDO21Info()
	info21.Options[protocol.OptionClientPIN] = false
	finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info21), conformance.RuleProfileRKUVCapabilityRequired)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation(
			[]conformance.FieldPath{"options.clientPin", "options.uv"},
			conformance.ExpectationAny,
			conformance.ExpectationTrue,
		),
	})

	info23 := validFIDO23Info()
	info23.Options[protocol.OptionClientPIN] = false
	assertNoAssessments(t, conformance.EvaluateGetInfo(info23))

	missingState := configNeutralFIDO23Info()
	missingState.Options[protocol.OptionResidentKeys] = true
	missingState.Options[protocol.OptionCredentialManagement] = true
	delete(missingState.Options, protocol.OptionClientPIN)
	missingState.MinPINLength = 0
	finding = requireOnlyFinding(t, conformance.EvaluateGetInfo(missingState), conformance.RuleProfileRKUVCapabilityRequired)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation(
			[]conformance.FieldPath{"options.clientPin", "options.uv"},
			conformance.ExpectationAny,
			conformance.ExpectationRequired,
		),
	})
}

func TestEvaluateGetInfoRequiresOnlyNormativeConfigCommands(t *testing.T) {
	tests := []struct {
		name string
		info func() protocol.AuthenticatorGetInfoResponse
		want []conformance.Expectation
	}{
		{
			name: "enterprise attestation",
			info: func() protocol.AuthenticatorGetInfoResponse {
				info := configNeutralFIDO23Info()
				info.Options[protocol.OptionEnterpriseAttestation] = false
				return info
			},
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x01"),
			},
		},
		{
			name: "set minimum PIN option",
			info: func() protocol.AuthenticatorGetInfoResponse {
				info := configNeutralFIDO23Info()
				info.Options[protocol.OptionSetMinPINLength] = true
				info.Extensions = append(info.Extensions, extension.ExtensionIdentifierMinPinLength)
				info.MaxRPIDsForSetMinPINLength = ptr(uint(3))
				return info
			},
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x03"),
			},
		},
		{
			name: "minimum PIN extension",
			info: func() protocol.AuthenticatorGetInfoResponse {
				info := configNeutralFIDO23Info()
				info.Extensions = append(info.Extensions, extension.ExtensionIdentifierMinPinLength)
				return info
			},
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"options.setMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationTrue),
				expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x03"),
				expectation([]conformance.FieldPath{"maxRPIDsForSetMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
		{
			name: "configurable PIN complexity",
			info: func() protocol.AuthenticatorGetInfoResponse {
				info := configNeutralFIDO23Info()
				info.Extensions = append(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)
				info.PinComplexityPolicy = ptr(false)
				return info
			},
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"options.setMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationTrue),
				expectation([]conformance.FieldPath{"extensions"}, conformance.ExpectationAll, conformance.ExpectationContains, "minPinLength"),
				expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x03"),
				expectation([]conformance.FieldPath{"maxRPIDsForSetMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
		{
			name: "vendor prototype",
			info: func() protocol.AuthenticatorGetInfoResponse {
				info := configNeutralFIDO23Info()
				info.VendorPrototypeConfigCommands = []protocol.VendorCommandID{}
				return info
			},
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0xFF"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := conformance.EvaluateGetInfo(test.info())
			if len(report.Findings) != 1 || len(report.Inconclusive) != 0 {
				t.Fatalf("report = %#v, want exactly one finding", report)
			}
			assertExpectations(t, report.Findings[0].Expectations, test.want)
		})
	}
}

func TestEvaluateGetInfoChecksConfigCommandPrerequisitesInTheSupportedDirection(t *testing.T) {
	tests := []struct {
		name    string
		command protocol.ConfigSubCommand
		rule    conformance.RuleID
		want    []conformance.Expectation
	}{
		{
			name:    "enable enterprise attestation requires ep",
			command: protocol.ConfigSubCommandEnableEnterpriseAttestation,
			rule:    conformance.RuleConfigCommandPrerequisite,
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"options.ep"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
		{
			name:    "toggle always UV requires alwaysUv",
			command: protocol.ConfigSubCommandToggleAlwaysUv,
			rule:    conformance.RuleConfigCommandPrerequisite,
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"options.alwaysUv"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
		{
			name:    "set minimum PIN requires its feature projections",
			command: protocol.ConfigSubCommandSetMinPINLength,
			rule:    conformance.RuleSetMinPINSupportConsistency,
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"options.setMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationTrue),
				expectation([]conformance.FieldPath{"extensions"}, conformance.ExpectationAll, conformance.ExpectationContains, "minPinLength"),
				expectation([]conformance.FieldPath{"maxRPIDsForSetMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
		{
			name:    "enable long touch requires longTouchForReset",
			command: protocol.ConfigSubCommandEnableLongTouchForReset,
			rule:    conformance.RuleConfigCommandPrerequisite,
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"longTouchForReset"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
		{
			name:    "vendor prototype requires command IDs member",
			command: protocol.ConfigSubCommandVendorPrototype,
			rule:    conformance.RuleConfigCommandPrerequisite,
			want: []conformance.Expectation{
				expectation([]conformance.FieldPath{"vendorPrototypeConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationRequired),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := configNeutralFIDO23Info()
			info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{test.command}
			finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), test.rule)
			assertExpectations(t, finding.Expectations, test.want)
		})
	}
}

func TestEvaluateGetInfoDoesNotInventOptionalConfigCommands(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.AuthenticatorGetInfoResponse)
	}{
		{
			name: "alwaysUv true",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Options[protocol.OptionAlwaysUv] = true
			},
		},
		{
			name: "alwaysUv false",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Options[protocol.OptionAlwaysUv] = false
			},
		},
		{
			name: "long touch true",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.LongTouchForReset = ptr(true)
			},
		},
		{
			name: "long touch false",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.LongTouchForReset = ptr(false)
			},
		},
		{
			name:   "authnrCfg without inventory",
			mutate: func(*protocol.AuthenticatorGetInfoResponse) {},
		},
		{
			name: "unknown command",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{0x80}
			},
		},
		{
			name: "duplicate unknown command",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{0x80, 0x80}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := configNeutralFIDO23Info()
			test.mutate(&info)
			assertNoAssessments(t, conformance.EvaluateGetInfo(info))
		})
	}
}

func TestEvaluateGetInfoRequiresObservableBuiltInUVForAlwaysUVWithU2F(t *testing.T) {
	for _, test := range []struct {
		name          string
		info          protocol.AuthenticatorGetInfoResponse
		specification conformance.SpecificationID
	}{
		{name: "FIDO 2.1", info: validFIDO21Info(), specification: conformance.SpecificationCTAP21},
		{name: "FIDO 2.3", info: validFIDO23Info(), specification: conformance.SpecificationCTAP23},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := test.info
			info.Versions = append(info.Versions, protocol.U2F_V2)
			info.Options[protocol.OptionAlwaysUv] = true
			delete(info.Options, protocol.OptionUserVerification)

			finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleAlwaysUVU2FRequiresBuiltInUV)
			assertExpectations(t, finding.Expectations, []conformance.Expectation{
				expectation([]conformance.FieldPath{"options.uv"}, conformance.ExpectationAll, conformance.ExpectationTrue),
			})
			if len(finding.References) != 1 || finding.References[0] != (conformance.RequirementRef{
				ID:            conformance.RequirementID(string(test.specification) + ":7.2.4:always-uv-disabled-u2f-must-not-be-advertised"),
				Specification: test.specification,
				Section:       "7.2.4",
				Clause:        "always-uv-disabled-u2f-must-not-be-advertised",
				URL:           finding.References[0].URL,
				Level:         conformance.RequirementMustNot,
			}) {
				t.Fatalf("references = %#v, want %s", finding.References, test.specification)
			}

			if !strings.HasSuffix(finding.References[0].URL, "#sctn-feature-descriptions-alwaysUv") {
				t.Fatalf("reference URL = %q", finding.References[0].URL)
			}
		})
	}

	t.Run("observable alternatives do not produce a static finding", func(t *testing.T) {
		for _, mutate := range []func(*protocol.AuthenticatorGetInfoResponse){
			func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Options[protocol.OptionAlwaysUv] = false
				info.Versions = append(info.Versions, protocol.U2F_V2)
			},
			func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Options[protocol.OptionAlwaysUv] = true
				info.Options[protocol.OptionUserVerification] = true
				info.Versions = append(info.Versions, protocol.U2F_V2)
			},
			func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Options[protocol.OptionAlwaysUv] = true
			},
		} {
			info := validFIDO23Info()
			mutate(&info)
			assertNoAssessments(t, conformance.EvaluateGetInfo(info))
		}
	})

	t.Run("unconfigured built-in UV does not protect U2F", func(t *testing.T) {
		info := validFIDO23Info()
		info.Versions = append(info.Versions, protocol.U2F_V2)
		info.Options[protocol.OptionAlwaysUv] = true
		info.Options[protocol.OptionUserVerification] = false
		requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleAlwaysUVU2FRequiresBuiltInUV)
	})
}

func TestEvaluateGetInfoDistinguishesAbsentAndPresentConfigInventory(t *testing.T) {
	info := configNeutralFIDO23Info()
	delete(info.Options, protocol.OptionAuthenticatorConfig)
	assertNoAssessments(t, conformance.EvaluateGetInfo(info))

	info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{}
	finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleAuthenticatorConfigSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"options.authnrCfg"}, conformance.ExpectationAll, conformance.ExpectationTrue),
	})
}

func TestEvaluateGetInfoAggregatesSetMinPINSupportProjections(t *testing.T) {
	info := validFIDO23Info()
	info.AuthenticatorConfigCommands = nil
	info.PinComplexityPolicy = ptr(false)
	info.Extensions = append(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)

	finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleSetMinPINSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x03"),
	})
	if len(finding.Evidence) < 4 {
		t.Fatalf("evidence = %#v, want all aggregated triggers", finding.Evidence)
	}
}

func TestEvaluateGetInfoSetMinPINReferencesFollowActualTriggers(t *testing.T) {
	const prefix = "ctap-2.3-ps-20260226:"
	option := conformance.RequirementID(prefix + "6.4:set-min-pin-length-option-reflects-subcommand-support")
	commands := conformance.RequirementID(prefix + "6.4:authenticator-config-commands-indicate-command-support")
	minimumExtension := conformance.RequirementID(prefix + "9:item-7-minimum-pin-length-extension-requires-config-subcommand")
	complexity := conformance.RequirementID(prefix + "7.5:configurable-pin-complexity-requires-set-min-pin-length")
	feature := conformance.RequirementID(prefix + "7.4:set-min-pin-length-feature-requires-extension-and-subcommand")
	inventory := conformance.RequirementID(prefix + "6.11.4:set-min-pin-length-must-be-in-inventory")
	maxRPIDs := conformance.RequirementID(prefix + "6.4:max-rpids-present-iff-set-min-pin-supported")

	tests := []struct {
		name   string
		mutate func(*protocol.AuthenticatorGetInfoResponse)
		want   []conformance.RequirementID
	}{
		{
			name: "stray max RP IDs",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.MaxRPIDsForSetMinPINLength = ptr(uint(3))
			},
			want: []conformance.RequirementID{maxRPIDs},
		},
		{
			name: "option only",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Options[protocol.OptionSetMinPINLength] = true
			},
			want: []conformance.RequirementID{option, feature, inventory, maxRPIDs},
		},
		{
			name: "command only",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}
			},
			want: []conformance.RequirementID{commands, option, feature, maxRPIDs},
		},
		{
			name: "minimum PIN extension only",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Extensions = append(info.Extensions, extension.ExtensionIdentifierMinPinLength)
			},
			want: []conformance.RequirementID{minimumExtension, option, inventory, maxRPIDs},
		},
		{
			name: "minimum PIN extension and command",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Extensions = append(info.Extensions, extension.ExtensionIdentifierMinPinLength)
				info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}
			},
			want: []conformance.RequirementID{commands, minimumExtension, option, maxRPIDs},
		},
		{
			name: "PIN complexity",
			mutate: func(info *protocol.AuthenticatorGetInfoResponse) {
				info.Extensions = append(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)
				info.PinComplexityPolicy = ptr(true)
			},
			want: []conformance.RequirementID{complexity, option, feature, inventory, maxRPIDs},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := configNeutralFIDO23Info()
			test.mutate(&info)
			finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleSetMinPINSupportConsistency)
			got := make([]conformance.RequirementID, 0, len(finding.References))
			for _, reference := range finding.References {
				got = append(got, reference.ID)
			}

			if !slices.Equal(got, test.want) {
				t.Fatalf("reference IDs = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestEvaluateGetInfoReportsAllMissingRequiredCommandsDeterministically(t *testing.T) {
	info := validFIDO23Info()
	info.AuthenticatorConfigCommands = nil
	info.Options[protocol.OptionEnterpriseAttestation] = false
	info.VendorPrototypeConfigCommands = []protocol.VendorCommandID{}

	report := conformance.EvaluateGetInfo(info)
	if len(report.Findings) != 3 || len(report.Inconclusive) != 0 {
		t.Fatalf("report = %#v, want three findings", report)
	}
	want := []struct {
		rule  conformance.RuleID
		value string
	}{
		{conformance.RuleSetMinPINSupportConsistency, "0x03"},
		{conformance.RuleConfigCommandRequired, "0x01"},
		{conformance.RuleConfigCommandRequired, "0xFF"},
	}

	for index, expected := range want {
		finding := report.Findings[index]
		if finding.RuleID != expected.rule || !findingHasExpectedValue(finding, expected.value) {
			t.Fatalf("finding[%d] = %#v, want %s/%s", index, finding, expected.rule, expected.value)
		}
	}

	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	second, err := json.Marshal(conformance.EvaluateGetInfo(info))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(first, second) {
		t.Fatalf("evaluation is not deterministic:\n%s\n%s", first, second)
	}
}

func TestEvaluateGetInfoStrictFIDO21IgnoresCTAP23OnlyInventory(t *testing.T) {
	info := validFIDO21Info()
	info.Options[protocol.OptionSetMinPINLength] = false
	info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}

	finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleSetMinPINSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"maxRPIDsForSetMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationAbsent),
	})
}

func TestEvaluateGetInfoAgainstRejectsNonCanonicalTargets(t *testing.T) {
	for _, target := range []conformance.Target{
		{Specification: conformance.SpecificationCTAP23, Profile: conformance.ProfileFIDO21},
		{Specification: conformance.SpecificationCTAP21, Profile: conformance.ProfileFIDO23},
		{Specification: conformance.SpecificationCTAP21, Profile: conformance.ProfileFIDO21Pre},
		{Specification: conformance.SpecificationCTAP20, Profile: conformance.ProfileU2FV2},
	} {
		_, err := conformance.EvaluateGetInfoAgainst(validFIDO21Info(), target)
		if !failure.IsCode(err, failure.CodeConformanceTargetInvalid) {
			t.Fatalf("target %#v: error = %v, want %s", target, err, failure.CodeConformanceTargetInvalid)
		}

		if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
			t.Fatalf("target %#v: phase = %q, want %q", target, got, failure.PhaseValidation)
		}

		params := failure.Snapshot(err).Params
		if params["specification"] != string(target.Specification) || params["profile"] != string(target.Profile) {
			t.Fatalf("target %#v: params = %#v, want specification/profile", target, params)
		}
	}

	report, err := conformance.EvaluateGetInfoAgainst(validFIDO23Info(), conformance.Target{
		Specification: conformance.SpecificationCTAP23,
		Profile:       conformance.ProfileFIDO23,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAssessments(t, report)
}

func TestEvaluateGetInfoAllowsDeclaredMaxMessageSize(t *testing.T) {
	for _, value := range []uint{0, 512, 1024, 4096} {
		info := validFIDO23Info()
		info.MaxMsgSize = value
		assertNoAssessments(t, conformance.EvaluateGetInfo(info))
	}
}

func TestEvaluateGetInfoValidatesOptionalListShape(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.AuthenticatorGetInfoResponse)
		rule   conformance.RuleID
	}{
		{"empty PIN protocols", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{}
		}, conformance.RulePinUVAuthProtocolsNonEmpty},
		{"duplicate PIN protocols", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{2, 2}
		}, conformance.RulePinUVAuthProtocolsUnique},
		{"empty transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Transports = []credential.AuthenticatorTransport{}
		}, conformance.RuleTransportsNonEmpty},
		{"duplicate transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Transports = []credential.AuthenticatorTransport{"usb", "usb"}
		}, conformance.RuleTransportsUnique},
		{"empty algorithms", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Algorithms = []credential.PublicKeyCredentialParameters{}
		}, conformance.RuleAlgorithmsNonEmpty},
		{"canonical duplicate algorithms", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Algorithms = []credential.PublicKeyCredentialParameters{
				{Algorithm: -7},
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -7},
			}
		}, conformance.RuleAlgorithmsUnique},
		{"empty reset transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.TransportsForReset = []credential.AuthenticatorTransport{}
		}, conformance.RuleTransportsForResetNonEmpty},
		{"duplicate reset transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.TransportsForReset = []credential.AuthenticatorTransport{"usb", "usb"}
		}, conformance.RuleTransportsForResetUnique},
		{"empty attestation formats", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.AttestationFormats = []attestation.AttestationStatementFormatIdentifier{}
		}, conformance.RuleAttestationFormatsNonEmpty},
		{"duplicate attestation formats", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.AttestationFormats = []attestation.AttestationStatementFormatIdentifier{"packed", "packed"}
		}, conformance.RuleAttestationFormatsUnique},
		{"none attestation format", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.AttestationFormats = []attestation.AttestationStatementFormatIdentifier{"none"}
		}, conformance.RuleAttestationFormatsNoneOmitted},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := validFIDO23Info()
			test.mutate(&info)
			requireOnlyFinding(t, conformance.EvaluateGetInfo(info), test.rule)
		})
	}
}

func TestEvaluateGetInfoUsesEditionSpecificCertificationRanges(t *testing.T) {
	info21 := validFIDO21Info()
	info21.Certifications = map[string]uint64{"FIDO": 7, "CCN-CPSTIC": 2, "future-certification": 999}
	finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info21), conformance.RuleCertificationLevelRange)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"certifications.FIDO"}, conformance.ExpectationAll, conformance.ExpectationRange, "1", "6"),
	})

	info23 := validFIDO23Info()
	info23.Certifications = map[string]uint64{"CCN-CPSTIC": 2, "future-certification": 999}
	finding = requireOnlyFinding(t, conformance.EvaluateGetInfo(info23), conformance.RuleCertificationLevelRange)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"certifications.CCN-CPSTIC"}, conformance.ExpectationAll, conformance.ExpectationRange, "1", "1"),
	})
}

func TestEvaluateGetInfoReferencesMatchResolvedTarget(t *testing.T) {
	for _, info := range []protocol.AuthenticatorGetInfoResponse{validFIDO21Info(), validFIDO23Info()} {
		info.Extensions = slices.DeleteFunc(info.Extensions, func(value extension.ExtensionIdentifier) bool {
			return value == extension.ExtensionIdentifierHMACSecret
		})
		report := conformance.EvaluateGetInfo(info)
		if report.Target == nil {
			t.Fatal("resolved fixture returned a nil target")
		}

		for _, finding := range report.Findings {
			for _, reference := range finding.References {
				if reference.Specification != report.Target.Specification {
					t.Fatalf("finding reference %#v does not match target %#v", reference, report.Target)
				}
			}
		}

		for _, inconclusive := range report.Inconclusive {
			for _, reference := range inconclusive.References {
				if reference.Specification != report.Target.Specification {
					t.Fatalf("inconclusive reference %#v does not match target %#v", reference, report.Target)
				}
			}
		}
	}
}

func TestEvaluateGetInfoKeepsUnobservableExceptionsInconclusive(t *testing.T) {
	t.Run("credential management may be built in", func(t *testing.T) {
		info := validFIDO23Info()
		delete(info.Options, protocol.OptionCredentialManagement)
		result := requireOnlyInconclusive(t, conformance.EvaluateGetInfo(info), conformance.RuleProfileRKCredentialManagementRequired)
		if result.Reason != conformance.EvidenceGapAuthenticatorUIUnknown {
			t.Fatalf("reason = %s", result.Reason)
		}
	})

	t.Run("credential protection may be implicit", func(t *testing.T) {
		info := validFIDO23Info()
		info.Extensions = slices.DeleteFunc(info.Extensions, func(value extension.ExtensionIdentifier) bool {
			return value == extension.ExtensionIdentifierCredentialProtection
		})
		result := requireOnlyInconclusive(t, conformance.EvaluateGetInfo(info), conformance.RuleProfileCredentialProtectionRequired)
		if result.Reason != conformance.EvidenceGapImplicitCredProtectUnknown {
			t.Fatalf("reason = %s", result.Reason)
		}
	})

	t.Run("built-in PIN entry cannot be inferred", func(t *testing.T) {
		info := configNeutralFIDO23Info()
		delete(info.Options, protocol.OptionClientPIN)
		info.Options[protocol.OptionUserVerification] = false
		info.MinPINLength = 0
		info.Options[protocol.OptionSetMinPINLength] = true
		info.Extensions = append(info.Extensions, extension.ExtensionIdentifierMinPinLength)
		info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}
		info.MaxRPIDsForSetMinPINLength = ptr(uint(3))
		result := requireOnlyInconclusive(t, conformance.EvaluateGetInfo(info), conformance.RuleSetMinPINRequiresPINCapability)
		if result.Reason != conformance.EvidenceGapBuiltInPINEntryUnknown {
			t.Fatalf("reason = %s", result.Reason)
		}
	})

	t.Run("FIDO 2.1 requires ClientPIN evidence", func(t *testing.T) {
		info := validFIDO21Info()
		delete(info.Options, protocol.OptionClientPIN)
		delete(info.Options, protocol.OptionResidentKeys)
		info.Options[protocol.OptionUserVerification] = false
		info.MinPINLength = 0
		finding := requireOnlyFinding(t, conformance.EvaluateGetInfo(info), conformance.RuleSetMinPINRequiresPINCapability)
		if len(finding.References) != 1 ||
			finding.References[0].Specification != conformance.SpecificationCTAP21 ||
			finding.References[0].Section != "7.4" ||
			finding.References[0].Level != conformance.RequirementMust {
			t.Fatalf("references = %#v, want CTAP 2.1 section 7.4 MUST", finding.References)
		}
	})
}

func TestEvaluateGetInfoSetMinPINFalseDoesNotRequirePINCapability(t *testing.T) {
	info21 := validFIDO21Info()
	info21.Options[protocol.OptionSetMinPINLength] = false
	delete(info21.Options, protocol.OptionClientPIN)
	delete(info21.Options, protocol.OptionResidentKeys)
	info21.MinPINLength = 0
	info21.MaxRPIDsForSetMinPINLength = nil
	info21.Extensions = slices.DeleteFunc(info21.Extensions, func(value extension.ExtensionIdentifier) bool {
		return value == extension.ExtensionIdentifierMinPinLength
	})
	assertNoAssessments(t, conformance.EvaluateGetInfo(info21))

	info23 := configNeutralFIDO23Info()
	info23.Options[protocol.OptionSetMinPINLength] = false
	delete(info23.Options, protocol.OptionClientPIN)
	info23.MinPINLength = 0
	assertNoAssessments(t, conformance.EvaluateGetInfo(info23))
}

func TestEvaluateGetInfoJSONContractIsTypedAndDeterministic(t *testing.T) {
	valid := conformance.EvaluateGetInfo(validFIDO23Info())
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}

	text := string(raw)
	for _, want := range []string{`"advertisedProfiles":["FIDO_2_3"]`, `"findings":[]`, `"inconclusive":[]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON %s does not contain %s", text, want)
		}
	}

	for _, legacy := range []string{`"args"`, `"conformanceFindings"`, `"expectation"`} {
		if strings.Contains(text, legacy) {
			t.Fatalf("legacy field %s leaked into %s", legacy, text)
		}
	}
	unresolved, err := json.Marshal(conformance.EvaluateGetInfo(protocol.AuthenticatorGetInfoResponse{}))
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{`"target":null`, `"advertisedProfiles":[]`, `"findings":[]`, `"inconclusive":[]`} {
		if !strings.Contains(string(unresolved), want) {
			t.Fatalf("unresolved JSON %s does not contain %s", unresolved, want)
		}
	}

	info := validFIDO23Info()
	info.AuthenticatorConfigCommands = nil
	invalid := conformance.EvaluateGetInfo(info)
	for _, finding := range invalid.Findings {
		if len(finding.References) == 0 {
			t.Fatalf("finding has no normative references: %#v", finding)
		}

		for _, reference := range finding.References {
			if reference.Section == "9.7" || reference.Section == "9.8" {
				t.Fatalf("mandatory item encoded as a fake subsection: %#v", reference)
			}
		}
	}

	first, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}

	second, err := json.Marshal(conformance.EvaluateGetInfo(info))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(first, second) {
		t.Fatalf("JSON is not deterministic:\n%s\n%s", first, second)
	}

	if !strings.Contains(string(first), `"values":[]`) {
		t.Fatalf("empty typed values serialized as null: %s", first)
	}
}

func validFIDO21Info() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_1},
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierCredentialProtection,
			extension.ExtensionIdentifierMinPinLength,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionResidentKeys:         true,
			protocol.OptionClientPIN:            true,
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionAuthenticatorConfig:  true,
			protocol.OptionSetMinPINLength:      true,
			protocol.OptionAlwaysUv:             false,
		},
		PinUvAuthProtocols:         []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		MinPINLength:               4,
		MaxRPIDsForSetMinPINLength: ptr(uint(3)),
	}
}

func validFIDO23Info() protocol.AuthenticatorGetInfoResponse {
	info := validFIDO21Info()
	info.Versions = protocol.Versions{protocol.FIDO_2_3}
	info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}

	return info
}

func configNeutralFIDO23Info() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierCredentialProtection,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN:           true,
			protocol.OptionPinUvAuthToken:      true,
			protocol.OptionAuthenticatorConfig: true,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		MinPINLength:       4,
	}
}

func expectation(subjects []conformance.FieldPath, quantifier conformance.ExpectationQuantifier, kind conformance.ExpectationKind, values ...string) conformance.Expectation {
	return conformance.Expectation{
		Subjects:   subjects,
		Quantifier: quantifier,
		Kind:       kind,
		Values:     values,
	}
}

func assertNoAssessments(t *testing.T, report conformance.Report) {
	t.Helper()

	if len(report.Findings) != 0 || len(report.Inconclusive) != 0 {
		t.Fatalf("report = %#v, want no assessments", report)
	}
}

func requireOnlyFinding(t *testing.T, report conformance.Report, rule conformance.RuleID) conformance.Finding {
	t.Helper()

	if len(report.Findings) != 1 || len(report.Inconclusive) != 0 {
		t.Fatalf("report = %#v, want exactly one finding", report)
	}

	if report.Findings[0].RuleID != rule {
		t.Fatalf("rule = %s, want %s; finding = %#v", report.Findings[0].RuleID, rule, report.Findings[0])
	}

	return report.Findings[0]
}

func requireOnlyInconclusive(t *testing.T, report conformance.Report, rule conformance.RuleID) conformance.Inconclusive {
	t.Helper()

	if len(report.Findings) != 0 || len(report.Inconclusive) != 1 {
		t.Fatalf("report = %#v, want exactly one inconclusive assessment", report)
	}

	if report.Inconclusive[0].RuleID != rule {
		t.Fatalf("rule = %s, want %s; result = %#v", report.Inconclusive[0].RuleID, rule, report.Inconclusive[0])
	}

	return report.Inconclusive[0]
}

func assertExpectations(t *testing.T, got, want []conformance.Expectation) {
	t.Helper()

	if !slices.EqualFunc(got, want, func(left, right conformance.Expectation) bool {
		return slices.Equal(left.Subjects, right.Subjects) &&
			left.Quantifier == right.Quantifier &&
			left.Kind == right.Kind &&
			slices.Equal(left.Values, right.Values)
	}) {
		t.Fatalf("expectations = %#v, want %#v", got, want)
	}
}

func hasExpectedValue(report conformance.Report, value string) bool {
	for _, finding := range report.Findings {
		if findingHasExpectedValue(finding, value) {
			return true
		}
	}

	return false
}

func findingHasExpectedValue(finding conformance.Finding, value string) bool {
	for _, expected := range finding.Expectations {
		if slices.Contains(expected.Values, value) {
			return true
		}
	}

	return false
}

func ptr[T any](value T) *T {
	return &value
}
