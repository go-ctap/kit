package conformance_test

import (
	"slices"
	"testing"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/conformance"
)

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

func validConfigNeutralFIDO23Info() protocol.AuthenticatorGetInfoResponse {
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
		if expectationsContainValue(finding.Expectations, value) {
			return true
		}
	}

	return false
}

func expectationsContainValue(expectations []conformance.Expectation, value string) bool {
	return slices.ContainsFunc(expectations, func(expectation conformance.Expectation) bool {
		return slices.Contains(expectation.Values, value)
	})
}

func ptr[T any](value T) *T {
	return &value
}
