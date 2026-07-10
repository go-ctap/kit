package conformance

import (
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
)

func pinRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       RuleSetMinPINRequiresPINCapability,
			selector: selectCTAP21Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(context.target, "7.4", "set-min-pin-length-requires-client-pin", "#sctn-feature-descriptions-setMinPINLength", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionSetMinPINLength) || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				return finding(
					[]FieldPath{"options.clientPin"},
					expected(ExpectationRequired),
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
		{
			id:       RuleSetMinPINRequiresPINCapability,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(context.target, "7.4", "set-min-pin-length-requires-client-pin-or-built-in-pin", "#sctn-feature-descriptions-setMinPINLength", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !setMinSupportExpected(context) || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}
				if !optionPresent(context.info, protocol.OptionUserVerification) {
					return finding(
						[]FieldPath{"options.clientPin", "options.uv"},
						expectedAny(ExpectationRequired),
						observedOption(context.info, protocol.OptionSetMinPINLength),
						observedOption(context.info, protocol.OptionClientPIN),
						observedOption(context.info, protocol.OptionUserVerification),
					)
				}
				if context.info.UvModality != nil && (*context.info.UvModality&protocol.UserVerifyPasscodeInternal) != 0 {
					return nil
				}

				evidence := []Evidence{
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
				}
				if context.info.UvModality == nil {
					evidence = append(evidence, observed("uvModality", EvidenceAbsent))
				} else {
					evidence = append(evidence, observedUnsigned("uvModality", uint(*context.info.UvModality)))
				}

				return inconclusive(
					[]FieldPath{"options.clientPin", "uvModality"},
					expectedAny(ExpectationRequired),
					EvidenceGapBuiltInPINEntryUnknown,
					evidence...,
				)
			},
		},
		{
			id:         RuleSetMinPINSupportConsistency,
			selector:   selectCTAP21Document,
			references: func(*getInfoContext) []RequirementRef { return nil },
			evaluate: func(context *getInfoContext) []assessment {
				maxRPIDsReference := getInfoRequirement(context.target, "max-rpids-present-iff-set-min-pin-supported", RequirementMust)
				optionReference := getInfoRequirement(context.target, "set-min-pin-length-option-reflects-subcommand-support", RequirementConstraint)
				featureReference := featureRequirement(context.target, "7.4", "set-min-pin-length-feature-requires-extension-and-subcommand", "#sctn-feature-descriptions-setMinPINLength", RequirementMust)
				if !optionTrue(context.info, protocol.OptionSetMinPINLength) {
					if context.info.MaxRPIDsForSetMinPINLength == nil {
						return nil
					}

					return []assessment{findingWithReferences(
						[]FieldPath{"maxRPIDsForSetMinPINLength"},
						expected(ExpectationAbsent),
						[]Evidence{
							observedOption(context.info, protocol.OptionSetMinPINLength),
							observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength),
						},
						maxRPIDsReference,
					)}
				}

				expectations := make([]Expectation, 0, 2)
				references := []RequirementRef{optionReference}
				if !slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
					expectations = append(expectations, expectedFor([]FieldPath{"extensions"}, ExpectationContains, "minPinLength"))
					references = append(references, featureReference)
				}
				if context.info.MaxRPIDsForSetMinPINLength == nil {
					expectations = append(expectations, expectedFor([]FieldPath{"maxRPIDsForSetMinPINLength"}, ExpectationRequired))
					references = append(references, maxRPIDsReference)
				}
				if len(expectations) == 0 {
					return nil
				}

				evidence := []Evidence{
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				}
				if context.info.MaxRPIDsForSetMinPINLength == nil {
					evidence = append(evidence, observed("maxRPIDsForSetMinPINLength", EvidenceAbsent))
				} else {
					evidence = append(evidence, observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength))
				}

				return findingWithExpectations(expectations, evidence, references...)
			},
		},
		{
			id:         RuleSetMinPINSupportConsistency,
			selector:   selectCTAP23Document,
			references: func(*getInfoContext) []RequirementRef { return nil },
			evaluate: func(context *getInfoContext) []assessment {
				maxRPIDsReference := getInfoRequirement(context.target, "max-rpids-present-iff-set-min-pin-supported", RequirementMust)
				optionReference := getInfoRequirement(context.target, "set-min-pin-length-option-reflects-subcommand-support", RequirementConstraint)
				commandsReference := getInfoRequirement(context.target, "authenticator-config-commands-indicate-command-support", RequirementConstraint)
				featureReference := featureRequirement(context.target, "7.4", "set-min-pin-length-feature-requires-extension-and-subcommand", "#sctn-feature-descriptions-setMinPINLength", RequirementMust)
				inventoryReference := configRequirement("6.11.4", "set-min-pin-length-must-be-in-inventory", "#setMinPINLength", RequirementMust)
				minimumExtensionReference := mandatoryRequirement(context.target, "7", "minimum-pin-length-extension-requires-config-subcommand")
				complexityReference := featureRequirement(context.target, "7.5", "configurable-pin-complexity-requires-set-min-pin-length", "#sctn-feature-descriptions-pinComplexityPolicy", RequirementMust)
				if !setMinSupportExpected(context) {
					if context.info.MaxRPIDsForSetMinPINLength == nil {
						return nil
					}

					return []assessment{findingWithReferences(
						[]FieldPath{"maxRPIDsForSetMinPINLength"},
						expected(ExpectationAbsent),
						[]Evidence{
							observedOption(context.info, protocol.OptionSetMinPINLength),
							observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands)),
							observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength),
						},
						maxRPIDsReference,
					)}
				}

				expectations := make([]Expectation, 0, 4)
				references := make([]RequirementRef, 0, 8)
				if optionTrue(context.info, protocol.OptionSetMinPINLength) {
					references = append(references, optionReference)
				}
				if slices.Contains(context.info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandSetMinPINLength)) {
					references = append(references, commandsReference)
				}
				if slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
					references = append(references, minimumExtensionReference)
				}
				if context.info.PinComplexityPolicy != nil && slices.Contains(context.info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
					references = append(references, complexityReference)
				}
				if !optionTrue(context.info, protocol.OptionSetMinPINLength) {
					expectations = append(expectations, expectedFor([]FieldPath{"options.setMinPINLength"}, ExpectationTrue))
					references = append(references, optionReference)
				}
				if !slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
					expectations = append(expectations, expectedFor([]FieldPath{"extensions"}, ExpectationContains, "minPinLength"))
					references = append(references, featureReference)
				}
				commandMissing := !slices.Contains(context.info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandSetMinPINLength))
				if commandMissing {
					expectations = append(expectations, expectedFor([]FieldPath{"authenticatorConfigCommands"}, ExpectationContains, "0x03"))
					references = append(references, inventoryReference)
				}
				if context.info.MaxRPIDsForSetMinPINLength == nil {
					expectations = append(expectations, expectedFor([]FieldPath{"maxRPIDsForSetMinPINLength"}, ExpectationRequired))
					references = append(references, maxRPIDsReference)
				}
				if len(expectations) == 0 {
					return nil
				}

				evidence := []Evidence{
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands)),
				}
				if context.info.MaxRPIDsForSetMinPINLength == nil {
					evidence = append(evidence, observed("maxRPIDsForSetMinPINLength", EvidenceAbsent))
				} else {
					evidence = append(evidence, observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength))
				}
				if context.info.PinComplexityPolicy != nil {
					state := EvidenceFalse
					if *context.info.PinComplexityPolicy {
						state = EvidenceTrue
					}
					evidence = append(evidence, observed("pinComplexityPolicy", state))
				}
				return findingWithExpectations(expectations, evidence, references...)
			},
		},
		{
			id:       RuleMinPINLengthMinimum,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "minimum-pin-length-at-least-four", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MinPINLength == nil || *context.info.MinPINLength >= 4 {
					return nil
				}

				return finding(
					[]FieldPath{"minPINLength"},
					expected(ExpectationMinimum, "4"),
					observedUnsigned("minPINLength", *context.info.MinPINLength),
				)
			},
		},
		{
			id:       RuleMinPINLengthRequiresClientPIN,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "min-pin-length-requires-client-pin", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MinPINLength == nil || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				return finding(
					[]FieldPath{"minPINLength"},
					expected(ExpectationAbsent),
					observedUnsigned("minPINLength", *context.info.MinPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
		{
			id:       RuleClientPINRequiresMinPINLength,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "client-pin-requires-min-pin-length", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionPresent(context.info, protocol.OptionClientPIN) || context.info.MinPINLength != nil {
					return nil
				}

				return finding(
					[]FieldPath{"minPINLength"},
					expected(ExpectationRequired),
					observedOption(context.info, protocol.OptionClientPIN),
					observed("minPINLength", EvidenceAbsent),
				)
			},
		},
		{
			id:       RuleMaxPINLengthMinimum,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "maximum-pin-length-at-least-eight", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxPINLength == nil || *context.info.MaxPINLength >= 8 {
					return nil
				}

				return finding(
					[]FieldPath{"maxPINLength"},
					expected(ExpectationMinimum, "8"),
					observedUnsigned("maxPINLength", *context.info.MaxPINLength),
				)
			},
		},
		{
			id:       RuleMaxPINLengthRequiresClientPIN,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "max-pin-length-requires-client-pin", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxPINLength == nil || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				return finding(
					[]FieldPath{"maxPINLength"},
					expected(ExpectationAbsent),
					observedUnsigned("maxPINLength", *context.info.MaxPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
		{
			id:       RulePinComplexityRequiresClientPIN,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(context.target, "7.5", "pin-complexity-requires-client-pin", "#sctn-feature-descriptions-pinComplexityPolicy", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.PinComplexityPolicy == nil || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				state := EvidenceFalse
				if *context.info.PinComplexityPolicy {
					state = EvidenceTrue
				}

				return finding(
					[]FieldPath{"pinComplexityPolicy"},
					expected(ExpectationAbsent),
					observed("pinComplexityPolicy", state),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
	}
}

func setMinSupportExpected(context *getInfoContext) bool {
	if optionTrue(context.info, protocol.OptionSetMinPINLength) {
		return true
	}
	if context.target.Specification != SpecificationCTAP23 {
		return false
	}
	if slices.Contains(context.info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandSetMinPINLength)) {
		return true
	}
	if context.target.Profile == ProfileFIDO23 && slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
		return true
	}

	return context.info.PinComplexityPolicy != nil && slices.Contains(context.info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)
}
