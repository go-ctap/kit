package conformance

import (
	"slices"
	"strconv"
)

func structuralRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       RuleVersionsRequired,
			selector: selectAny,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "versions-required", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if len(context.info.Versions) > 0 {
					return nil
				}

				state := EvidenceAbsent
				if context.info.Versions != nil {
					state = EvidencePresentEmpty
				}

				return finding(
					[]FieldPath{"versions"},
					expected(ExpectationNonEmpty),
					observed("versions", state),
				)
			},
		},
		listNonEmptyRule(
			RulePinUVAuthProtocolsNonEmpty,
			selectCTAP21OrLater,
			"pinUvAuthProtocols",
			"pin-uv-auth-protocols-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.PinUvAuthProtocols != nil, pinProtocolValues(context.info)
			},
		),
		listUniqueRule(
			RulePinUVAuthProtocolsUnique,
			selectCTAP21OrLater,
			"pinUvAuthProtocols",
			"pin-uv-auth-protocols-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.PinUvAuthProtocols != nil, pinProtocolValues(context.info)
			},
		),
		listNonEmptyRule(
			RuleTransportsNonEmpty,
			selectCTAP21OrLater,
			"transports",
			"transports-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Transports != nil, stringValues(context.info.Transports)
			},
		),
		listUniqueRule(
			RuleTransportsUnique,
			selectCTAP21OrLater,
			"transports",
			"transports-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Transports != nil, stringValues(context.info.Transports)
			},
		),
		listNonEmptyRule(
			RuleAlgorithmsNonEmpty,
			selectCTAP21OrLater,
			"algorithms",
			"algorithms-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Algorithms != nil, algorithmValues(context.info.Algorithms)
			},
		),
		listUniqueRule(
			RuleAlgorithmsUnique,
			selectCTAP21OrLater,
			"algorithms",
			"algorithms-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.Algorithms != nil, algorithmValues(context.info.Algorithms)
			},
		),
		listNonEmptyRule(
			RuleTransportsForResetNonEmpty,
			selectCTAP23Document,
			"transportsForReset",
			"transports-for-reset-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.TransportsForReset != nil, stringValues(context.info.TransportsForReset)
			},
		),
		listUniqueRule(
			RuleTransportsForResetUnique,
			selectCTAP23Document,
			"transportsForReset",
			"transports-for-reset-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.TransportsForReset != nil, stringValues(context.info.TransportsForReset)
			},
		),
		listNonEmptyRule(
			RuleAttestationFormatsNonEmpty,
			selectCTAP23Document,
			"attestationFormats",
			"attestation-formats-nonempty",
			func(context *getInfoContext) (bool, []string) {
				return context.info.AttestationFormats != nil, stringValues(context.info.AttestationFormats)
			},
		),
		listUniqueRule(
			RuleAttestationFormatsUnique,
			selectCTAP23Document,
			"attestationFormats",
			"attestation-formats-unique",
			func(context *getInfoContext) (bool, []string) {
				return context.info.AttestationFormats != nil, stringValues(context.info.AttestationFormats)
			},
		),
		{
			id:       RuleAttestationFormatsNoneOmitted,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "attestation-format-none-omitted", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !slices.Contains(context.info.AttestationFormats, "none") {
					return nil
				}

				return finding(
					[]FieldPath{"attestationFormats"},
					expected(ExpectationExcludes, "none"),
					observedStrings("attestationFormats", true, stringValues(context.info.AttestationFormats)),
				)
			},
		},
		{
			id:       RuleCertificationLevelRange,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(
					context.target,
					"7.3.1",
					"defined-certification-level-ranges",
					"#sctn-authenticator-certifications-authenticator-actions",
					RequirementConstraint,
				)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				type certificationRange struct {
					id       string
					minimum  uint64
					maximum  uint64
					fromCTAP SpecificationID
				}

				ranges := []certificationRange{
					{id: "FIPS-CMVP-2", minimum: 1, maximum: 4, fromCTAP: SpecificationCTAP21},
					{id: "FIPS-CMVP-3", minimum: 1, maximum: 4, fromCTAP: SpecificationCTAP21},
					{id: "FIPS-CMVP-2-PHY", minimum: 1, maximum: 4, fromCTAP: SpecificationCTAP21},
					{id: "FIPS-CMVP-3-PHY", minimum: 1, maximum: 4, fromCTAP: SpecificationCTAP21},
					{id: "CC-EAL", minimum: 1, maximum: 7, fromCTAP: SpecificationCTAP21},
					{id: "FIDO", minimum: 1, maximum: 6, fromCTAP: SpecificationCTAP21},
					{id: "CCN-CPSTIC", minimum: 1, maximum: 1, fromCTAP: SpecificationCTAP23},
				}

				results := make([]assessment, 0)
				for _, validRange := range ranges {
					if validRange.fromCTAP == SpecificationCTAP23 && context.target.Specification != SpecificationCTAP23 {
						continue
					}
					level, present := context.info.Certifications[validRange.id]
					if !present || (level >= validRange.minimum && level <= validRange.maximum) {
						continue
					}

					results = append(results, findingWithReferences(
						[]FieldPath{FieldPath("certifications." + validRange.id)},
						expected(
							ExpectationRange,
							strconv.FormatUint(validRange.minimum, 10),
							strconv.FormatUint(validRange.maximum, 10),
						),
						[]Evidence{observed(
							FieldPath("certifications."+validRange.id),
							EvidenceValue,
							strconv.FormatUint(level, 10),
						)},
					))
				}

				return results
			},
		},
	}
}

func listNonEmptyRule(id RuleID, selector func(*getInfoContext) bool, path FieldPath, clause string, value func(*getInfoContext) (bool, []string)) getInfoRule {
	return getInfoRule{
		id:       id,
		selector: selector,
		references: func(context *getInfoContext) []RequirementRef {
			return []RequirementRef{getInfoRequirement(context.target, clause, RequirementMustNot)}
		},
		evaluate: func(context *getInfoContext) []assessment {
			known, values := value(context)
			if !known || len(values) > 0 {
				return nil
			}

			return finding(
				[]FieldPath{path},
				expected(ExpectationNonEmpty),
				observed(path, EvidencePresentEmpty),
			)
		},
	}
}

func listUniqueRule(id RuleID, selector func(*getInfoContext) bool, path FieldPath, clause string, value func(*getInfoContext) (bool, []string)) getInfoRule {
	return getInfoRule{
		id:       id,
		selector: selector,
		references: func(context *getInfoContext) []RequirementRef {
			return []RequirementRef{getInfoRequirement(context.target, clause, RequirementMustNot)}
		},
		evaluate: func(context *getInfoContext) []assessment {
			known, values := value(context)
			if !known || !hasDuplicates(values) {
				return nil
			}

			return finding(
				[]FieldPath{path},
				expected(ExpectationUnique),
				observedStrings(path, true, values),
			)
		},
	}
}
