// These tests exercise the internal evaluator through its public DTO contract.
package conformance_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	engine "github.com/go-ctap/kit/internal/conformance"
	"github.com/go-ctap/kit/model/conformance"
)

func TestEvaluateGetInfoRequiresOnlyNormativeConfigCommands(t *testing.T) {
	tests := []struct {
		name string
		info func() protocol.AuthenticatorGetInfoResponse
		want []conformance.Expectation
	}{
		{
			name: "enterprise attestation",
			info: func() protocol.AuthenticatorGetInfoResponse {
				info := validConfigNeutralFIDO23Info()
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
				info := validConfigNeutralFIDO23Info()
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
				info := validConfigNeutralFIDO23Info()
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
				info := validConfigNeutralFIDO23Info()
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
				info := validConfigNeutralFIDO23Info()
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
			report := engine.EvaluateGetInfo(test.info())
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
			info := validConfigNeutralFIDO23Info()
			info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{test.command}
			finding := requireOnlyFinding(t, engine.EvaluateGetInfo(info), test.rule)
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
			info := validConfigNeutralFIDO23Info()
			test.mutate(&info)
			assertNoAssessments(t, engine.EvaluateGetInfo(info))
		})
	}
}

func TestEvaluateGetInfoDistinguishesAbsentAndPresentConfigInventory(t *testing.T) {
	info := validConfigNeutralFIDO23Info()
	delete(info.Options, protocol.OptionAuthenticatorConfig)
	assertNoAssessments(t, engine.EvaluateGetInfo(info))

	info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{}
	finding := requireOnlyFinding(t, engine.EvaluateGetInfo(info), conformance.RuleAuthenticatorConfigSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"options.authnrCfg"}, conformance.ExpectationAll, conformance.ExpectationTrue),
	})
}

func TestEvaluateGetInfoAggregatesSetMinPINSupportProjections(t *testing.T) {
	info := validFIDO23Info()
	info.AuthenticatorConfigCommands = nil
	info.PinComplexityPolicy = ptr(false)
	info.Extensions = append(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)

	finding := requireOnlyFinding(t, engine.EvaluateGetInfo(info), conformance.RuleSetMinPINSupportConsistency)
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
			info := validConfigNeutralFIDO23Info()
			test.mutate(&info)
			finding := requireOnlyFinding(t, engine.EvaluateGetInfo(info), conformance.RuleSetMinPINSupportConsistency)
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

	report := engine.EvaluateGetInfo(info)
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
		if finding.RuleID != expected.rule || !expectationsContainValue(finding.Expectations, expected.value) {
			t.Fatalf("finding[%d] = %#v, want %s/%s", index, finding, expected.rule, expected.value)
		}
	}

	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	second, err := json.Marshal(engine.EvaluateGetInfo(info))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(first, second) {
		t.Fatalf("evaluation is not deterministic:\n%s\n%s", first, second)
	}
}
