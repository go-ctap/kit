package conformance

import (
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
)

func pinRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       model.RuleSetMinPINRequiresPINCapability,
			selector: selectCTAP21Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(context.target, "7.4", "set-min-pin-length-requires-client-pin", "#sctn-feature-descriptions-setMinPINLength", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionSetMinPINLength) || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.clientPin"},
					expected(model.ExpectationRequired),
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
		{
			id:       model.RuleSetMinPINRequiresPINCapability,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(context.target, "7.4", "set-min-pin-length-requires-client-pin-or-built-in-pin", "#sctn-feature-descriptions-setMinPINLength", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !setMinSupportExpected(context) || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				if !optionPresent(context.info, protocol.OptionUserVerification) {
					return finding(
						[]model.FieldPath{"options.clientPin", "options.uv"},
						expectedAny(model.ExpectationRequired),
						observedOption(context.info, protocol.OptionSetMinPINLength),
						observedOption(context.info, protocol.OptionClientPIN),
						observedOption(context.info, protocol.OptionUserVerification),
					)
				}

				if context.info.UvModality != nil && (*context.info.UvModality&protocol.UserVerifyPasscodeInternal) != 0 {
					return nil
				}

				evidence := []model.Evidence{
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
				}

				if context.info.UvModality == nil {
					evidence = append(evidence, observed("uvModality", model.EvidenceAbsent))
				} else {
					evidence = append(evidence, observedUnsigned("uvModality", uint(*context.info.UvModality)))
				}

				return inconclusive(
					[]model.FieldPath{"options.clientPin", "uvModality"},
					expectedAny(model.ExpectationRequired),
					model.EvidenceGapBuiltInPINEntryUnknown,
					evidence...,
				)
			},
		},
		{
			id:         model.RuleSetMinPINSupportConsistency,
			selector:   selectCTAP21Document,
			references: func(*getInfoContext) []model.RequirementRef { return nil },
			evaluate: func(context *getInfoContext) []assessment {
				maxRPIDsReference := getInfoRequirement(context.target, "max-rpids-present-iff-set-min-pin-supported", model.RequirementMust)
				optionReference := getInfoRequirement(context.target, "set-min-pin-length-option-reflects-subcommand-support", model.RequirementConstraint)
				featureReference := featureRequirement(context.target, "7.4", "set-min-pin-length-feature-requires-extension-and-subcommand", "#sctn-feature-descriptions-setMinPINLength", model.RequirementMust)
				if !optionTrue(context.info, protocol.OptionSetMinPINLength) {
					if context.info.MaxRPIDsForSetMinPINLength == nil {
						return nil
					}

					return []assessment{findingWithReferences(
						[]model.FieldPath{"maxRPIDsForSetMinPINLength"},
						expected(model.ExpectationAbsent),
						[]model.Evidence{
							observedOption(context.info, protocol.OptionSetMinPINLength),
							observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength),
						},
						maxRPIDsReference,
					)}
				}

				expectations := make([]model.Expectation, 0, 2)
				references := []model.RequirementRef{optionReference}
				if !slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
					expectations = append(expectations, expectedFor([]model.FieldPath{"extensions"}, model.ExpectationContains, "minPinLength"))
					references = append(references, featureReference)
				}

				if context.info.MaxRPIDsForSetMinPINLength == nil {
					expectations = append(expectations, expectedFor([]model.FieldPath{"maxRPIDsForSetMinPINLength"}, model.ExpectationRequired))
					references = append(references, maxRPIDsReference)
				}

				if len(expectations) == 0 {
					return nil
				}

				evidence := []model.Evidence{
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				}

				if context.info.MaxRPIDsForSetMinPINLength == nil {
					evidence = append(evidence, observed("maxRPIDsForSetMinPINLength", model.EvidenceAbsent))
				} else {
					evidence = append(evidence, observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength))
				}

				return findingWithExpectations(expectations, evidence, references...)
			},
		},
		{
			id:         model.RuleSetMinPINSupportConsistency,
			selector:   selectCTAP23Document,
			references: func(*getInfoContext) []model.RequirementRef { return nil },
			evaluate: func(context *getInfoContext) []assessment {
				maxRPIDsReference := getInfoRequirement(context.target, "max-rpids-present-iff-set-min-pin-supported", model.RequirementMust)
				optionReference := getInfoRequirement(context.target, "set-min-pin-length-option-reflects-subcommand-support", model.RequirementConstraint)
				commandsReference := getInfoRequirement(context.target, "authenticator-config-commands-indicate-command-support", model.RequirementConstraint)
				featureReference := featureRequirement(context.target, "7.4", "set-min-pin-length-feature-requires-extension-and-subcommand", "#sctn-feature-descriptions-setMinPINLength", model.RequirementMust)
				inventoryReference := configRequirement("6.11.4", "set-min-pin-length-must-be-in-inventory", "#setMinPINLength", model.RequirementMust)
				minimumExtensionReference := mandatoryRequirement(context.target, "7", "minimum-pin-length-extension-requires-config-subcommand")
				complexityReference := featureRequirement(context.target, "7.5", "configurable-pin-complexity-requires-set-min-pin-length", "#sctn-feature-descriptions-pinComplexityPolicy", model.RequirementMust)
				if !setMinSupportExpected(context) {
					if context.info.MaxRPIDsForSetMinPINLength == nil {
						return nil
					}

					return []assessment{findingWithReferences(
						[]model.FieldPath{"maxRPIDsForSetMinPINLength"},
						expected(model.ExpectationAbsent),
						[]model.Evidence{
							observedOption(context.info, protocol.OptionSetMinPINLength),
							observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands)),
							observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength),
						},
						maxRPIDsReference,
					)}
				}

				expectations := make([]model.Expectation, 0, 4)
				references := make([]model.RequirementRef, 0, 8)
				if optionTrue(context.info, protocol.OptionSetMinPINLength) {
					references = append(references, optionReference)
				}

				if slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandSetMinPINLength) {
					references = append(references, commandsReference)
				}

				if slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
					references = append(references, minimumExtensionReference)
				}

				if context.info.PinComplexityPolicy != nil && slices.Contains(context.info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
					references = append(references, complexityReference)
				}

				if !optionTrue(context.info, protocol.OptionSetMinPINLength) {
					expectations = append(expectations, expectedFor([]model.FieldPath{"options.setMinPINLength"}, model.ExpectationTrue))
					references = append(references, optionReference)
				}

				if !slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
					expectations = append(expectations, expectedFor([]model.FieldPath{"extensions"}, model.ExpectationContains, "minPinLength"))
					references = append(references, featureReference)
				}

				commandMissing := !slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandSetMinPINLength)
				if commandMissing {
					expectations = append(expectations, expectedFor([]model.FieldPath{"authenticatorConfigCommands"}, model.ExpectationContains, "0x03"))
					references = append(references, inventoryReference)
				}

				if context.info.MaxRPIDsForSetMinPINLength == nil {
					expectations = append(expectations, expectedFor([]model.FieldPath{"maxRPIDsForSetMinPINLength"}, model.ExpectationRequired))
					references = append(references, maxRPIDsReference)
				}

				if len(expectations) == 0 {
					return nil
				}

				evidence := []model.Evidence{
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands)),
				}

				if context.info.MaxRPIDsForSetMinPINLength == nil {
					evidence = append(evidence, observed("maxRPIDsForSetMinPINLength", model.EvidenceAbsent))
				} else {
					evidence = append(evidence, observedUnsigned("maxRPIDsForSetMinPINLength", *context.info.MaxRPIDsForSetMinPINLength))
				}

				if context.info.PinComplexityPolicy != nil {
					state := model.EvidenceFalse
					if *context.info.PinComplexityPolicy {
						state = model.EvidenceTrue
					}
					evidence = append(evidence, observed("pinComplexityPolicy", state))
				}

				return findingWithExpectations(expectations, evidence, references...)
			},
		},
		{
			id:       model.RuleMinPINLengthMinimum,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "minimum-pin-length-at-least-four", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MinPINLength == 0 || context.info.MinPINLength >= 4 {
					return nil
				}

				return finding(
					[]model.FieldPath{"minPINLength"},
					expected(model.ExpectationMinimum, "4"),
					observedUnsigned("minPINLength", context.info.MinPINLength),
				)
			},
		},
		{
			id:       model.RuleMinPINLengthRequiresClientPIN,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "min-pin-length-requires-client-pin", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MinPINLength == 0 || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				return finding(
					[]model.FieldPath{"minPINLength"},
					expected(model.ExpectationAbsent),
					observedUnsigned("minPINLength", context.info.MinPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
		{
			id:       model.RuleClientPINRequiresMinPINLength,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "client-pin-requires-min-pin-length", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionPresent(context.info, protocol.OptionClientPIN) || context.info.MinPINLength != 0 {
					return nil
				}

				return finding(
					[]model.FieldPath{"minPINLength"},
					expected(model.ExpectationRequired),
					observedOption(context.info, protocol.OptionClientPIN),
					observed("minPINLength", model.EvidenceAbsent),
				)
			},
		},
		{
			id:       model.RuleMaxPINLengthMinimum,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "maximum-pin-length-at-least-eight", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxPINLength == 0 || context.info.MaxPINLength >= 8 {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxPINLength"},
					expected(model.ExpectationMinimum, "8"),
					observedUnsigned("maxPINLength", context.info.MaxPINLength),
				)
			},
		},
		{
			id:       model.RuleMaxPINLengthRequiresClientPIN,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "max-pin-length-requires-client-pin", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxPINLength == 0 || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxPINLength"},
					expected(model.ExpectationAbsent),
					observedUnsigned("maxPINLength", context.info.MaxPINLength),
					observedOption(context.info, protocol.OptionClientPIN),
				)
			},
		},
		{
			id:       model.RulePinComplexityRequiresClientPIN,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(context.target, "7.5", "pin-complexity-requires-client-pin", "#sctn-feature-descriptions-pinComplexityPolicy", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.PinComplexityPolicy == nil || optionPresent(context.info, protocol.OptionClientPIN) {
					return nil
				}

				state := model.EvidenceFalse
				if *context.info.PinComplexityPolicy {
					state = model.EvidenceTrue
				}

				return finding(
					[]model.FieldPath{"pinComplexityPolicy"},
					expected(model.ExpectationAbsent),
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

	if context.target.Specification != model.SpecificationCTAP23 {
		return false
	}

	if slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandSetMinPINLength) {
		return true
	}

	if context.target.Profile == model.ProfileFIDO23 && slices.Contains(context.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
		return true
	}

	return context.info.PinComplexityPolicy != nil && slices.Contains(context.info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)
}
