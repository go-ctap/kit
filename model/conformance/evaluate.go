package conformance

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/samber/lo"
)

var ErrInvalidTarget = errors.New("conformance: invalid target")

type assessmentOutcome uint8

const (
	assessmentFinding assessmentOutcome = iota + 1
	assessmentInconclusive
)

type assessment struct {
	outcome      assessmentOutcome
	expectations []Expectation
	evidence     []Evidence
	gap          EvidenceGapID
	references   []RequirementRef
}

type getInfoContext struct {
	info             protocol.AuthenticatorGetInfoResponse
	target           Target
	advertised       []Profile
	commandsKnown    bool
	inventoryApplies bool
}

type getInfoRule struct {
	id         RuleID
	selector   func(*getInfoContext) bool
	references func(*getInfoContext) []RequirementRef
	evaluate   func(*getInfoContext) []assessment
}

// EvaluateGetInfo resolves the highest stable advertised profile and evaluates
// the response against the immutable specification edition owned by that
// profile.
func EvaluateGetInfo(info protocol.AuthenticatorGetInfoResponse) Report {
	target, resolved := resolveTarget(info.Versions)
	if !resolved {
		return Report{
			AdvertisedProfiles: advertisedProfiles(info.Versions),
			Findings:           make([]Finding, 0),
			Inconclusive:       make([]Inconclusive, 0),
		}
	}

	return evaluateGetInfo(info, target)
}

// EvaluateGetInfoAgainst evaluates against an explicit canonical profile and
// specification pair. It rejects mixed-edition targets rather than producing
// findings whose rules and references come from different documents.
func EvaluateGetInfoAgainst(info protocol.AuthenticatorGetInfoResponse, target Target) (Report, error) {
	if !isCanonicalTarget(target) {
		return Report{}, fmt.Errorf(
			"%w: specification %q with profile %q",
			ErrInvalidTarget,
			target.Specification,
			target.Profile,
		)
	}

	return evaluateGetInfo(info, target), nil
}

func evaluateGetInfo(info protocol.AuthenticatorGetInfoResponse, target Target) Report {
	context := getInfoContext{
		info:       info,
		target:     target,
		advertised: advertisedProfiles(info.Versions),
	}
	context.inventoryApplies = target.Specification == SpecificationCTAP23
	context.commandsKnown = context.inventoryApplies && info.AuthenticatorConfigCommands != nil

	report := Report{
		Target:             &target,
		AdvertisedProfiles: context.advertised,
		Findings:           make([]Finding, 0),
		Inconclusive:       make([]Inconclusive, 0),
	}
	activeRules := make(map[RuleID]bool)
	seen := make(map[string]bool)

	for _, rule := range getInfoRules {
		if !rule.selector(&context) {
			continue
		}
		if activeRules[rule.id] {
			panic("conformance: multiple rule variants selected for " + string(rule.id))
		}
		activeRules[rule.id] = true

		baseReferences := rule.references(&context)
		for _, result := range rule.evaluate(&context) {
			references := lo.UniqBy(
				append(slices.Clone(baseReferences), result.references...),
				func(reference RequirementRef) RequirementID { return reference.ID },
			)
			validateAssessmentReferences(target, references)
			key := assessmentKey(rule.id, result)
			if seen[key] {
				continue
			}
			seen[key] = true

			switch result.outcome {
			case assessmentFinding:
				report.Findings = append(report.Findings, Finding{
					RuleID:       rule.id,
					Profile:      target.Profile,
					Expectations: nonNil(result.expectations),
					Evidence:     nonNil(result.evidence),
					References:   nonNil(references),
				})
			case assessmentInconclusive:
				report.Inconclusive = append(report.Inconclusive, Inconclusive{
					RuleID:       rule.id,
					Profile:      target.Profile,
					Reason:       result.gap,
					Expectations: nonNil(result.expectations),
					Evidence:     nonNil(result.evidence),
					References:   nonNil(references),
				})
			}
		}
	}

	return report
}

func validateAssessmentReferences(target Target, references []RequirementRef) {
	for _, reference := range references {
		if reference.Specification != target.Specification {
			panic(fmt.Sprintf(
				"conformance: reference %q uses %q for target %q",
				reference.ID,
				reference.Specification,
				target.Specification,
			))
		}
	}
}

func assessmentKey(id RuleID, result assessment) string {
	parts := []string{string(id), string(result.outcome), string(result.gap)}
	for _, expectation := range result.expectations {
		parts = append(parts, string(expectation.Quantifier), string(expectation.Kind))
		for _, subject := range expectation.Subjects {
			parts = append(parts, string(subject))
		}
		parts = append(parts, expectation.Values...)
	}

	return strings.Join(parts, "\x00")
}

func finding(subjects []FieldPath, expectation Expectation, evidence ...Evidence) []assessment {
	expectation.Subjects = nonNil(subjects)
	return []assessment{{
		outcome:      assessmentFinding,
		expectations: []Expectation{expectation},
		evidence:     evidence,
	}}
}

func findingWithReferences(subjects []FieldPath, expectation Expectation, evidence []Evidence, references ...RequirementRef) assessment {
	expectation.Subjects = nonNil(subjects)
	return assessment{
		outcome:      assessmentFinding,
		expectations: []Expectation{expectation},
		evidence:     evidence,
		references:   references,
	}
}

func findingWithExpectations(expectations []Expectation, evidence []Evidence, references ...RequirementRef) []assessment {
	return []assessment{{
		outcome:      assessmentFinding,
		expectations: nonNil(expectations),
		evidence:     evidence,
		references:   references,
	}}
}

func inconclusive(subjects []FieldPath, expectation Expectation, gap EvidenceGapID, evidence ...Evidence) []assessment {
	expectation.Subjects = nonNil(subjects)
	return []assessment{{
		outcome:      assessmentInconclusive,
		expectations: []Expectation{expectation},
		gap:          gap,
		evidence:     evidence,
	}}
}

func expected(kind ExpectationKind, values ...string) Expectation {
	return Expectation{Quantifier: ExpectationAll, Kind: kind, Values: nonNil(values)}
}

func expectedAny(kind ExpectationKind, values ...string) Expectation {
	return Expectation{Quantifier: ExpectationAny, Kind: kind, Values: nonNil(values)}
}

func expectedFor(subjects []FieldPath, kind ExpectationKind, values ...string) Expectation {
	expectation := expected(kind, values...)
	expectation.Subjects = nonNil(subjects)

	return expectation
}

func observed(path FieldPath, state EvidenceState, values ...string) Evidence {
	return Evidence{Path: path, State: state, Values: nonNil(values)}
}

func observedOption(info protocol.AuthenticatorGetInfoResponse, option protocol.Option) Evidence {
	path := FieldPath("options." + string(option))
	value, ok := info.Options[option]
	if !ok {
		return observed(path, EvidenceAbsent)
	}
	if value {
		return observed(path, EvidenceTrue)
	}

	return observed(path, EvidenceFalse)
}

func observedStrings(path FieldPath, known bool, values []string) Evidence {
	if !known {
		return observed(path, EvidenceAbsent)
	}
	if len(values) == 0 {
		return observed(path, EvidencePresentEmpty)
	}

	return observed(path, EvidencePresent, values...)
}

func observedUnsigned(path FieldPath, value uint) Evidence {
	return observed(path, EvidenceValue, strconv.FormatUint(uint64(value), 10))
}

func optionPresent(info protocol.AuthenticatorGetInfoResponse, option protocol.Option) bool {
	_, ok := info.Options[option]

	return ok
}

func optionTrue(info protocol.AuthenticatorGetInfoResponse, option protocol.Option) bool {
	value, ok := info.Options[option]

	return ok && value
}

func extensionValues(info protocol.AuthenticatorGetInfoResponse) []string {
	values := make([]string, 0, len(info.Extensions))
	for _, value := range info.Extensions {
		values = append(values, string(value))
	}

	return values
}

func pinProtocolValues(info protocol.AuthenticatorGetInfoResponse) []string {
	values := make([]string, 0, len(info.PinUvAuthProtocols))
	for _, value := range info.PinUvAuthProtocols {
		values = append(values, strconv.FormatUint(uint64(value), 10))
	}

	return values
}

func unsignedValues(values []uint) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, fmt.Sprintf("0x%02X", value))
	}

	return result
}

func algorithmValues(values []credential.PublicKeyCredentialParameters) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		typ := value.Type
		if typ == "" {
			typ = credential.PublicKeyCredentialTypePublicKey
		}
		result = append(result, fmt.Sprintf("%s:%d", typ, value.Algorithm))
	}

	return result
}

func hasDuplicates(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}

	return false
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return make([]T, 0)
	}

	return values
}

func selectAny(*getInfoContext) bool { return true }

func selectCTAP21OrLater(context *getInfoContext) bool {
	return context.target.Profile == ProfileFIDO21 || context.target.Profile == ProfileFIDO23
}

func selectFIDO21(context *getInfoContext) bool { return context.target.Profile == ProfileFIDO21 }

func selectFIDO23(context *getInfoContext) bool { return context.target.Profile == ProfileFIDO23 }

func selectCTAP21Document(context *getInfoContext) bool {
	return context.target.Specification == SpecificationCTAP21
}

func selectCTAP23Document(context *getInfoContext) bool {
	return context.target.Specification == SpecificationCTAP23
}

func selectConfigInventory(context *getInfoContext) bool { return context.inventoryApplies }

func selectCommandsKnown(context *getInfoContext) bool { return context.commandsKnown }
