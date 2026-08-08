// These tests exercise the public assessment API as an external consumer.
package conformance_test

import (
	"slices"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/model/failure"
)

func TestAssessGetInfoAcceptsVersionSpecificProfiles(t *testing.T) {
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
			report := conformance.AssessGetInfo(test.info)
			if report.Target == nil || *report.Target != test.target {
				t.Fatalf("target = %#v, want %#v", report.Target, test.target)
			}
			assertNoAssessments(t, report)
		})
	}
}

func TestAssessGetInfoScreenshotRegressionIsProfileSpecific(t *testing.T) {
	info := validFIDO21Info()
	info.Options[protocol.OptionLargeBlobs] = true
	info.MaxSerializedLargeBlobArray = 1024

	report21 := conformance.AssessGetInfo(info)
	assertNoAssessments(t, report21)

	info.Versions = protocol.Versions{protocol.FIDO_2_3}
	report23 := conformance.AssessGetInfo(info)
	finding := requireOnlyFinding(t, report23, conformance.RuleSetMinPINSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"authenticatorConfigCommands"}, conformance.ExpectationAll, conformance.ExpectationContains, "0x03"),
	})
	if hasExpectedValue(report23, "0x02") {
		t.Fatal("alwaysUv=false incorrectly required toggleAlwaysUv (0x02)")
	}
}

func TestAssessGetInfoResolvesProfilesIndependentlyOfVersionOrder(t *testing.T) {
	info := validFIDO23Info()
	info.Versions = protocol.Versions{
		protocol.FIDO_2_1,
		protocol.FIDO_2_0,
		protocol.FIDO_2_3,
		protocol.FIDO_2_1_PRE,
	}

	report := conformance.AssessGetInfo(info)
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

func TestAssessGetInfoUsesStableTargetsAndLeavesOtherProfilesUnresolved(t *testing.T) {
	t.Run("preview does not outrank stable FIDO 2.0", func(t *testing.T) {
		report := conformance.AssessGetInfo(protocol.AuthenticatorGetInfoResponse{
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
			report := conformance.AssessGetInfo(protocol.AuthenticatorGetInfoResponse{Versions: test.versions})
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

func TestAssessGetInfoDoesNotPromoteFIDO22NoteToNormativeFinding(t *testing.T) {
	t.Run("identifier only remains unresolved", func(t *testing.T) {
		const fido22 protocol.Version = "FIDO_2_2"

		report := conformance.AssessGetInfo(protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{fido22},
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
			assertNoAssessments(t, conformance.AssessGetInfo(info))
		})
	}
}

func TestAssessGetInfoStrictFIDO21IgnoresCTAP23OnlyInventory(t *testing.T) {
	info := validFIDO21Info()
	info.Options[protocol.OptionSetMinPINLength] = false
	info.AuthenticatorConfigCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength}

	finding := requireOnlyFinding(t, conformance.AssessGetInfo(info), conformance.RuleSetMinPINSupportConsistency)
	assertExpectations(t, finding.Expectations, []conformance.Expectation{
		expectation([]conformance.FieldPath{"maxRPIDsForSetMinPINLength"}, conformance.ExpectationAll, conformance.ExpectationAbsent),
	})
}

func TestAssessGetInfoAgainstRejectsNonCanonicalTargets(t *testing.T) {
	for _, target := range []conformance.Target{
		{Specification: conformance.SpecificationCTAP23, Profile: conformance.ProfileFIDO21},
		{Specification: conformance.SpecificationCTAP21, Profile: conformance.ProfileFIDO23},
		{Specification: conformance.SpecificationCTAP21, Profile: conformance.ProfileFIDO21Pre},
		{Specification: conformance.SpecificationCTAP20, Profile: conformance.ProfileU2FV2},
	} {
		_, err := conformance.AssessGetInfoAgainst(validFIDO21Info(), target)
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

	report, err := conformance.AssessGetInfoAgainst(validFIDO23Info(), conformance.Target{
		Specification: conformance.SpecificationCTAP23,
		Profile:       conformance.ProfileFIDO23,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAssessments(t, report)
}

func TestAssessGetInfoReferencesMatchResolvedTarget(t *testing.T) {
	for _, info := range []protocol.AuthenticatorGetInfoResponse{validFIDO21Info(), validFIDO23Info()} {
		info.Extensions = slices.DeleteFunc(info.Extensions, func(value extension.ExtensionIdentifier) bool {
			return value == extension.ExtensionIdentifierHMACSecret
		})
		report := conformance.AssessGetInfo(info)
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
