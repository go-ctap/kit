// These tests exercise the public assessment API as an external consumer.
package conformance_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

func TestAssessGetInfoSeparatesFIDO21AndFIDO23RKSemantics(t *testing.T) {
	info21 := validFIDO21Info()
	info21.Options[protocol.OptionClientPIN] = false
	finding := requireOnlyFinding(t, conformance.AssessGetInfo(info21), conformance.RuleProfileRKUVCapabilityRequired)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation(
			[]conformance.FieldPath{"options.clientPin", "options.uv"},
			conformance.ExpectationAny,
			conformance.ExpectationTrue,
		),
	})

	info23 := validFIDO23Info()
	info23.Options[protocol.OptionClientPIN] = false
	assertNoAssessments(t, conformance.AssessGetInfo(info23))

	missingState := validConfigNeutralFIDO23Info()
	missingState.Options[protocol.OptionResidentKeys] = true
	missingState.Options[protocol.OptionCredentialManagement] = true
	delete(missingState.Options, protocol.OptionClientPIN)
	missingState.MinPINLength = 0
	finding = requireOnlyFinding(t, conformance.AssessGetInfo(missingState), conformance.RuleProfileRKUVCapabilityRequired)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation(
			[]conformance.FieldPath{"options.clientPin", "options.uv"},
			conformance.ExpectationAny,
			conformance.ExpectationRequired,
		),
	})
}

func TestAssessGetInfoRequiresObservableBuiltInUVForAlwaysUVWithU2F(t *testing.T) {
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

			finding := requireOnlyFinding(t, conformance.AssessGetInfo(info), conformance.RuleAlwaysUVU2FRequiresBuiltInUV)
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
			assertNoAssessments(t, conformance.AssessGetInfo(info))
		}
	})

	t.Run("unconfigured built-in UV does not protect U2F", func(t *testing.T) {
		info := validFIDO23Info()
		info.Versions = append(info.Versions, protocol.U2F_V2)
		info.Options[protocol.OptionAlwaysUv] = true
		info.Options[protocol.OptionUserVerification] = false
		requireOnlyFinding(t, conformance.AssessGetInfo(info), conformance.RuleAlwaysUVU2FRequiresBuiltInUV)
	})
}

func TestAssessGetInfoUsesEditionSpecificCertificationRanges(t *testing.T) {
	info21 := validFIDO21Info()
	info21.Certifications = map[string]uint64{"FIDO": 7, "CCN-CPSTIC": 2, "future-certification": 999}
	finding := requireOnlyFinding(t, conformance.AssessGetInfo(info21), conformance.RuleCertificationLevelRange)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"certifications.FIDO"}, conformance.ExpectationAll, conformance.ExpectationRange, "1", "6"),
	})

	info23 := validFIDO23Info()
	info23.Certifications = map[string]uint64{"CCN-CPSTIC": 2, "future-certification": 999}
	finding = requireOnlyFinding(t, conformance.AssessGetInfo(info23), conformance.RuleCertificationLevelRange)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"certifications.CCN-CPSTIC"}, conformance.ExpectationAll, conformance.ExpectationRange, "1", "1"),
	})
}

func TestAssessGetInfoKeepsUnobservableExceptionsInconclusive(t *testing.T) {
	t.Run("credential management may be built in", func(t *testing.T) {
		info := validFIDO23Info()
		delete(info.Options, protocol.OptionCredentialManagement)
		result := requireOnlyInconclusive(t, conformance.AssessGetInfo(info), conformance.RuleProfileRKCredentialManagementRequired)
		if result.Reason != conformance.EvidenceGapAuthenticatorUIUnknown {
			t.Fatalf("reason = %s", result.Reason)
		}
	})

	t.Run("credential protection may be implicit", func(t *testing.T) {
		info := validFIDO23Info()
		info.Extensions = slices.DeleteFunc(info.Extensions, func(value extension.ExtensionIdentifier) bool {
			return value == extension.ExtensionIdentifierCredentialProtection
		})
		result := requireOnlyInconclusive(t, conformance.AssessGetInfo(info), conformance.RuleProfileCredentialProtectionRequired)
		if result.Reason != conformance.EvidenceGapImplicitCredProtectUnknown {
			t.Fatalf("reason = %s", result.Reason)
		}
	})

	t.Run("built-in PIN entry cannot be inferred", func(t *testing.T) {
		info := validConfigNeutralFIDO23Info()
		delete(info.Options, protocol.OptionClientPIN)
		info.Options[protocol.OptionUserVerification] = false
		info.MinPINLength = 0
		info.Options[protocol.OptionSetMinPINLength] = true
		info.Extensions = append(info.Extensions, extension.ExtensionIdentifierMinPinLength)
		info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}
		info.MaxRPIDsForSetMinPINLength = ptr(uint(3))
		result := requireOnlyInconclusive(t, conformance.AssessGetInfo(info), conformance.RuleSetMinPINRequiresPINCapability)
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
		finding := requireOnlyFinding(t, conformance.AssessGetInfo(info), conformance.RuleSetMinPINRequiresPINCapability)
		if len(finding.References) != 1 ||
			finding.References[0].Specification != conformance.SpecificationCTAP21 ||
			finding.References[0].Section != "7.4" ||
			finding.References[0].Level != conformance.RequirementMust {
			t.Fatalf("references = %#v, want CTAP 2.1 section 7.4 MUST", finding.References)
		}
	})
}

func TestAssessGetInfoSetMinPINFalseDoesNotRequirePINCapability(t *testing.T) {
	info21 := validFIDO21Info()
	info21.Options[protocol.OptionSetMinPINLength] = false
	delete(info21.Options, protocol.OptionClientPIN)
	delete(info21.Options, protocol.OptionResidentKeys)
	info21.MinPINLength = 0
	info21.MaxRPIDsForSetMinPINLength = nil
	info21.Extensions = slices.DeleteFunc(info21.Extensions, func(value extension.ExtensionIdentifier) bool {
		return value == extension.ExtensionIdentifierMinPinLength
	})
	assertNoAssessments(t, conformance.AssessGetInfo(info21))

	info23 := validConfigNeutralFIDO23Info()
	info23.Options[protocol.OptionSetMinPINLength] = false
	delete(info23.Options, protocol.OptionClientPIN)
	info23.MinPINLength = 0
	assertNoAssessments(t, conformance.AssessGetInfo(info23))
}
