package conformance

import (
	"slices"
	"strconv"

	model "github.com/go-ctap/kit/model/conformance"
)

func structuralRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       model.RuleVersionsRequired,
			selector: selectAny,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "versions-required", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if len(context.info.Versions) > 0 {
					return nil
				}

				state := model.EvidenceAbsent
				if context.info.Versions != nil {
					state = model.EvidencePresentEmpty
				}

				return finding(
					[]model.FieldPath{"versions"},
					expected(model.ExpectationNonEmpty),
					observed("versions", state),
				)
			},
		},
		listNonEmptyRule(
			model.RulePinUVAuthProtocolsNonEmpty,
			selectCTAP21OrLater,
			"pinUvAuthProtocols",
			"pin-uv-auth-protocols-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.PinUvAuthProtocols != nil, pinProtocolValues(context.info)
			},
		),
		listUniqueRule(
			model.RulePinUVAuthProtocolsUnique,
			selectCTAP21OrLater,
			"pinUvAuthProtocols",
			"pin-uv-auth-protocols-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.PinUvAuthProtocols != nil, pinProtocolValues(context.info)
			},
		),
		listNonEmptyRule(
			model.RuleTransportsNonEmpty,
			selectCTAP21OrLater,
			"transports",
			"transports-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Transports != nil, stringValues(context.info.Transports)
			},
		),
		listUniqueRule(
			model.RuleTransportsUnique,
			selectCTAP21OrLater,
			"transports",
			"transports-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Transports != nil, stringValues(context.info.Transports)
			},
		),
		listNonEmptyRule(
			model.RuleAlgorithmsNonEmpty,
			selectCTAP21OrLater,
			"algorithms",
			"algorithms-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Algorithms != nil, algorithmValues(context.info.Algorithms)
			},
		),
		listUniqueRule(
			model.RuleAlgorithmsUnique,
			selectCTAP21OrLater,
			"algorithms",
			"algorithms-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Algorithms != nil, algorithmValues(context.info.Algorithms)
			},
		),
		listNonEmptyRule(
			model.RuleTransportsForResetNonEmpty,
			selectCTAP23Document,
			"transportsForReset",
			"transports-for-reset-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.TransportsForReset != nil, stringValues(context.info.TransportsForReset)
			},
		),
		listUniqueRule(
			model.RuleTransportsForResetUnique,
			selectCTAP23Document,
			"transportsForReset",
			"transports-for-reset-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.TransportsForReset != nil, stringValues(context.info.TransportsForReset)
			},
		),
		listNonEmptyRule(
			model.RuleAttestationFormatsNonEmpty,
			selectCTAP23Document,
			"attestationFormats",
			"attestation-formats-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.AttestationFormats != nil, stringValues(context.info.AttestationFormats)
			},
		),
		listUniqueRule(
			model.RuleAttestationFormatsUnique,
			selectCTAP23Document,
			"attestationFormats",
			"attestation-formats-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.AttestationFormats != nil, stringValues(context.info.AttestationFormats)
			},
		),
		{
			id:       model.RuleAttestationFormatsNoneOmitted,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "attestation-format-none-omitted", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !slices.Contains(context.info.AttestationFormats, "none") {
					return nil
				}

				return finding(
					[]model.FieldPath{"attestationFormats"},
					expected(model.ExpectationExcludes, "none"),
					observedStrings("attestationFormats", true, stringValues(context.info.AttestationFormats)),
				)
			},
		},
		{
			id:       model.RuleCertificationLevelRange,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(
					context.target,
					"7.3.1",
					"defined-certification-level-ranges",
					"#sctn-authenticator-certifications-authenticator-actions",
					model.RequirementConstraint,
				)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				type certificationRange struct {
					id       string
					minimum  uint64
					maximum  uint64
					fromCTAP model.SpecificationID
				}

				ranges := []certificationRange{
					{id: "FIPS-CMVP-2", minimum: 1, maximum: 4, fromCTAP: model.SpecificationCTAP21},
					{id: "FIPS-CMVP-3", minimum: 1, maximum: 4, fromCTAP: model.SpecificationCTAP21},
					{id: "FIPS-CMVP-2-PHY", minimum: 1, maximum: 4, fromCTAP: model.SpecificationCTAP21},
					{id: "FIPS-CMVP-3-PHY", minimum: 1, maximum: 4, fromCTAP: model.SpecificationCTAP21},
					{id: "CC-EAL", minimum: 1, maximum: 7, fromCTAP: model.SpecificationCTAP21},
					{id: "FIDO", minimum: 1, maximum: 6, fromCTAP: model.SpecificationCTAP21},
					{id: "CCN-CPSTIC", minimum: 1, maximum: 1, fromCTAP: model.SpecificationCTAP23},
				}

				results := make([]assessment, 0)
				for _, validRange := range ranges {
					if validRange.fromCTAP == model.SpecificationCTAP23 && context.target.Specification != model.SpecificationCTAP23 {
						continue
					}

					level, present := context.info.Certifications[validRange.id]
					if !present || (level >= validRange.minimum && level <= validRange.maximum) {
						continue
					}

					results = append(results, findingWithReferences(
						[]model.FieldPath{model.FieldPath("certifications." + validRange.id)},
						expected(
							model.ExpectationRange,
							strconv.FormatUint(validRange.minimum, 10),
							strconv.FormatUint(validRange.maximum, 10),
						),
						[]model.Evidence{observed(
							model.FieldPath("certifications."+validRange.id),
							model.EvidenceValue,
							strconv.FormatUint(level, 10),
						)},
					))
				}

				return results
			},
		},
	}
}

func listNonEmptyRule(id model.RuleID, selector func(*getInfoContext) bool, path model.FieldPath, clause string, value func(*getInfoContext) (bool, []string)) getInfoRule {
	return getInfoRule{
		id:       id,
		selector: selector,
		references: func(context *getInfoContext) []model.RequirementRef {
			return []model.RequirementRef{getInfoRequirement(context.target, clause, model.RequirementMustNot)}
		},
		evaluate: func(context *getInfoContext) []assessment {
			known, values := value(context)
			if !known || len(values) > 0 {
				return nil
			}

			return finding(
				[]model.FieldPath{path},
				expected(model.ExpectationNonEmpty),
				observed(path, model.EvidencePresentEmpty),
			)
		},
	}
}

func listUniqueRule(id model.RuleID, selector func(*getInfoContext) bool, path model.FieldPath, clause string, value func(*getInfoContext) (bool, []string)) getInfoRule {
	return getInfoRule{
		id:       id,
		selector: selector,
		references: func(context *getInfoContext) []model.RequirementRef {
			return []model.RequirementRef{getInfoRequirement(context.target, clause, model.RequirementMustNot)}
		},
		evaluate: func(context *getInfoContext) []assessment {
			known, values := value(context)
			if !known || !hasDuplicates(values) {
				return nil
			}

			return finding(
				[]model.FieldPath{path},
				expected(model.ExpectationUnique),
				observedStrings(path, true, values),
			)
		},
	}
}
