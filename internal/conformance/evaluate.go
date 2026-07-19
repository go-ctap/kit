package conformance

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
	"github.com/go-ctap/kit/model/failure"
	"github.com/samber/lo"
)

type assessmentOutcome uint8

const (
	assessmentFinding assessmentOutcome = iota + 1
	assessmentInconclusive
)

type assessment struct {
	outcome      assessmentOutcome
	expectations []model.Expectation
	evidence     []model.Evidence
	gap          model.EvidenceGapID
	references   []model.RequirementRef
}

type getInfoContext struct {
	info             protocol.AuthenticatorGetInfoResponse
	target           model.Target
	advertised       []model.Profile
	commandsKnown    bool
	inventoryApplies bool
}

type getInfoRule struct {
	id         model.RuleID
	selector   func(*getInfoContext) bool
	references func(*getInfoContext) []model.RequirementRef
	evaluate   func(*getInfoContext) []assessment
}

// EvaluateGetInfo resolves the highest stable advertised profile and evaluates
// the response against the immutable specification edition owned by that
// profile.
func EvaluateGetInfo(info protocol.AuthenticatorGetInfoResponse) model.Report {
	target, resolved := resolveTarget(info.Versions)
	if !resolved {
		return model.Report{
			AdvertisedProfiles: advertisedProfiles(info.Versions),
			Findings:           make([]model.Finding, 0),
			Inconclusive:       make([]model.Inconclusive, 0),
		}
	}

	return evaluateGetInfo(info, target)
}

// EvaluateGetInfoAgainst evaluates against an explicit canonical profile and
// specification pair. It rejects mixed-edition targets rather than producing
// findings whose rules and references come from different documents.
func EvaluateGetInfoAgainst(info protocol.AuthenticatorGetInfoResponse, target model.Target) (model.Report, error) {
	if !isCanonicalTarget(target) {
		return model.Report{}, failure.New(failure.CodeConformanceTargetInvalid,
			failure.WithParams(map[string]string{
				"specification": string(target.Specification),
				"profile":       string(target.Profile),
			}),
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return evaluateGetInfo(info, target), nil
}

func evaluateGetInfo(info protocol.AuthenticatorGetInfoResponse, target model.Target) model.Report {
	context := getInfoContext{
		info:       info,
		target:     target,
		advertised: advertisedProfiles(info.Versions),
	}
	context.inventoryApplies = target.Specification == model.SpecificationCTAP23
	context.commandsKnown = context.inventoryApplies && info.AuthenticatorConfigCommands != nil

	report := model.Report{
		Target:             &target,
		AdvertisedProfiles: context.advertised,
		Findings:           make([]model.Finding, 0),
		Inconclusive:       make([]model.Inconclusive, 0),
	}
	activeRules := make(map[model.RuleID]bool)
	seen := make(map[string]bool)

	for _, rule := range getInfoRules {
		if !rule.selector(&context) {
			continue
		}

		if activeRules[rule.id] {
			continue
		}
		activeRules[rule.id] = true

		baseReferences := rule.references(&context)
		for _, result := range rule.evaluate(&context) {
			references := lo.Filter(lo.UniqBy(
				slices.Concat(baseReferences, result.references),
				func(reference model.RequirementRef) model.RequirementID { return reference.ID },
			), func(reference model.RequirementRef, _ int) bool {
				return reference.ID != "" && reference.Specification == target.Specification
			})
			key := assessmentKey(rule.id, result)
			if seen[key] {
				continue
			}
			seen[key] = true

			switch result.outcome {
			case assessmentFinding:
				report.Findings = append(report.Findings, model.Finding{
					RuleID:       rule.id,
					Profile:      target.Profile,
					Expectations: nonNil(result.expectations),
					Evidence:     nonNil(result.evidence),
					References:   nonNil(references),
				})
			case assessmentInconclusive:
				report.Inconclusive = append(report.Inconclusive, model.Inconclusive{
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

func assessmentKey(id model.RuleID, result assessment) string {
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

func finding(subjects []model.FieldPath, expectation model.Expectation, evidence ...model.Evidence) []assessment {
	expectation.Subjects = nonNil(subjects)
	return []assessment{{
		outcome:      assessmentFinding,
		expectations: []model.Expectation{expectation},
		evidence:     evidence,
	}}
}

func findingWithReferences(subjects []model.FieldPath, expectation model.Expectation, evidence []model.Evidence, references ...model.RequirementRef) assessment {
	expectation.Subjects = nonNil(subjects)
	return assessment{
		outcome:      assessmentFinding,
		expectations: []model.Expectation{expectation},
		evidence:     evidence,
		references:   references,
	}
}

func findingWithExpectations(expectations []model.Expectation, evidence []model.Evidence, references ...model.RequirementRef) []assessment {
	return []assessment{{
		outcome:      assessmentFinding,
		expectations: nonNil(expectations),
		evidence:     evidence,
		references:   references,
	}}
}

func inconclusive(subjects []model.FieldPath, expectation model.Expectation, gap model.EvidenceGapID, evidence ...model.Evidence) []assessment {
	expectation.Subjects = nonNil(subjects)
	return []assessment{{
		outcome:      assessmentInconclusive,
		expectations: []model.Expectation{expectation},
		gap:          gap,
		evidence:     evidence,
	}}
}

func expected(kind model.ExpectationKind, values ...string) model.Expectation {
	return model.Expectation{Quantifier: model.ExpectationAll, Kind: kind, Values: nonNil(values)}
}

func expectedAny(kind model.ExpectationKind, values ...string) model.Expectation {
	return model.Expectation{Quantifier: model.ExpectationAny, Kind: kind, Values: nonNil(values)}
}

func expectedFor(subjects []model.FieldPath, kind model.ExpectationKind, values ...string) model.Expectation {
	expectation := expected(kind, values...)
	expectation.Subjects = nonNil(subjects)

	return expectation
}

func observed(path model.FieldPath, state model.EvidenceState, values ...string) model.Evidence {
	return model.Evidence{Path: path, State: state, Values: nonNil(values)}
}

func observedOption(info protocol.AuthenticatorGetInfoResponse, option protocol.Option) model.Evidence {
	path := model.FieldPath("options." + string(option))
	value, ok := info.Options[option]
	if !ok {
		return observed(path, model.EvidenceAbsent)
	}

	if value {
		return observed(path, model.EvidenceTrue)
	}

	return observed(path, model.EvidenceFalse)
}

func observedStrings(path model.FieldPath, known bool, values []string) model.Evidence {
	if !known {
		return observed(path, model.EvidenceAbsent)
	}

	if len(values) == 0 {
		return observed(path, model.EvidencePresentEmpty)
	}

	return observed(path, model.EvidencePresent, values...)
}

func observedUnsigned(path model.FieldPath, value uint) model.Evidence {
	return observed(path, model.EvidenceValue, strconv.FormatUint(uint64(value), 10))
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

func unsignedValues[T ~uint | ~uint64](values []T) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, fmt.Sprintf("0x%02X", uint64(value)))
	}

	return result
}

func stringValues[T ~string](values []T) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
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
	return context.target.Profile == model.ProfileFIDO21 || context.target.Profile == model.ProfileFIDO23
}

func selectFIDO21(context *getInfoContext) bool { return context.target.Profile == model.ProfileFIDO21 }

func selectFIDO23(context *getInfoContext) bool { return context.target.Profile == model.ProfileFIDO23 }

func selectCTAP21Document(context *getInfoContext) bool {
	return context.target.Specification == model.SpecificationCTAP21
}

func selectCTAP23Document(context *getInfoContext) bool {
	return context.target.Specification == model.SpecificationCTAP23
}

func selectConfigInventory(context *getInfoContext) bool { return context.inventoryApplies }

func selectCommandsKnown(context *getInfoContext) bool { return context.commandsKnown }
