package conformance

import (
	"slices"

	"github.com/go-ctap/ctap/protocol"
)

func configRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       RuleAuthenticatorConfigSupportConsistency,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				references := []RequirementRef{
					getInfoRequirement(context.target, "authnr-cfg-true-means-authenticator-config-supported", RequirementConstraint),
				}

				if context.target.Specification == SpecificationCTAP23 {
					references = append(references, getInfoRequirement(context.target, "authenticator-config-commands-indicate-command-support", RequirementConstraint))
				}

				return references
			},
			evaluate: func(context *getInfoContext) []assessment {
				supportExpected := context.commandsKnown ||
					setMinSupportExpected(context) ||
					context.info.VendorPrototypeConfigCommands != nil ||
					(context.target.Profile == ProfileFIDO23 && optionPresent(context.info, protocol.OptionEnterpriseAttestation))
				if !supportExpected || optionTrue(context.info, protocol.OptionAuthenticatorConfig) {
					return nil
				}

				evidence := []Evidence{
					observedOption(context.info, protocol.OptionAuthenticatorConfig),
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedOption(context.info, protocol.OptionEnterpriseAttestation),
					observedStrings("vendorPrototypeConfigCommands", context.info.VendorPrototypeConfigCommands != nil, unsignedValues(context.info.VendorPrototypeConfigCommands)),
				}

				if context.target.Specification == SpecificationCTAP23 {
					evidence = append(evidence, observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands)))
				}

				return finding(
					[]FieldPath{"options.authnrCfg"},
					expected(ExpectationTrue),
					evidence...,
				)
			},
		},
		{
			id:       RuleConfigCommandRequired,
			selector: selectCTAP23Document,
			references: func(*getInfoContext) []RequirementRef {
				return nil
			},
			evaluate: func(context *getInfoContext) []assessment {
				results := make([]assessment, 0, 2)
				commands := observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands))

				if context.target.Profile == ProfileFIDO23 &&
					optionPresent(context.info, protocol.OptionEnterpriseAttestation) &&
					!slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandEnableEnterpriseAttestation) {
					results = append(results, findingWithReferences(
						[]FieldPath{"authenticatorConfigCommands"},
						expected(ExpectationContains, "0x01"),
						[]Evidence{observedOption(context.info, protocol.OptionEnterpriseAttestation), commands},
						mandatoryRequirement(context.target, "8", "enterprise-attestation-requires-config-subcommand"),
						configRequirement("6.11.1", "enable-enterprise-attestation-must-be-in-inventory", "#enableEnterpriseAttestation", RequirementMust),
					))
				}

				if context.info.VendorPrototypeConfigCommands != nil &&
					!slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandVendorPrototype) {
					results = append(results, findingWithReferences(
						[]FieldPath{"authenticatorConfigCommands"},
						expected(ExpectationContains, "0xFF"),
						[]Evidence{
							observedStrings("vendorPrototypeConfigCommands", true, unsignedValues(context.info.VendorPrototypeConfigCommands)),
							commands,
						},
						requirement(SpecificationCTAP23, "6.4", "vendor-prototype-command-list-means-subcommand-supported", ctap23URL+"#authenticatorGetInfo", RequirementConstraint),
						configRequirement("6.11.3", "vendor-prototype-must-be-in-inventory", "#vendorPrototype", RequirementMust),
					))
				}

				return results
			},
		},
		{
			id:       RuleConfigCommandPrerequisite,
			selector: selectCommandsKnown,
			references: func(*getInfoContext) []RequirementRef {
				return nil
			},
			evaluate: func(context *getInfoContext) []assessment {
				commands := observedStrings("authenticatorConfigCommands", true, unsignedValues(context.info.AuthenticatorConfigCommands))
				results := make([]assessment, 0, 4)
				add := func(command protocol.ConfigSubCommand, valid bool, subject FieldPath, expectation Expectation, evidence Evidence, reference RequirementRef) {
					if !slices.Contains(context.info.AuthenticatorConfigCommands, command) || valid {
						return
					}
					results = append(results, findingWithReferences(
						[]FieldPath{subject},
						expectation,
						[]Evidence{evidence, commands},
						reference,
					))
				}

				add(
					protocol.ConfigSubCommandEnableEnterpriseAttestation,
					optionPresent(context.info, protocol.OptionEnterpriseAttestation),
					"options.ep",
					expected(ExpectationRequired),
					observedOption(context.info, protocol.OptionEnterpriseAttestation),
					configRequirement("6.11.1", "enable-enterprise-attestation-only-if-feature-supported", "#enableEnterpriseAttestation", RequirementConstraint),
				)
				add(
					protocol.ConfigSubCommandToggleAlwaysUv,
					optionPresent(context.info, protocol.OptionAlwaysUv),
					"options.alwaysUv",
					expected(ExpectationRequired),
					observedOption(context.info, protocol.OptionAlwaysUv),
					configRequirement("6.11.2", "toggle-always-uv-only-if-feature-supported", "#toggleAlwaysUv", RequirementConstraint),
				)

				longTouchState := EvidenceAbsent
				if context.info.LongTouchForReset != nil {
					longTouchState = EvidenceFalse
					if *context.info.LongTouchForReset {
						longTouchState = EvidenceTrue
					}
				}
				add(
					protocol.ConfigSubCommandEnableLongTouchForReset,
					context.info.LongTouchForReset != nil,
					"longTouchForReset",
					expected(ExpectationRequired),
					observed("longTouchForReset", longTouchState),
					configRequirement("6.11.5", "enable-long-touch-only-if-feature-supported", "#enableLongTouchForReset", RequirementConstraint),
				)
				add(
					protocol.ConfigSubCommandVendorPrototype,
					context.info.VendorPrototypeConfigCommands != nil,
					"vendorPrototypeConfigCommands",
					expected(ExpectationRequired),
					observedStrings("vendorPrototypeConfigCommands", context.info.VendorPrototypeConfigCommands != nil, unsignedValues(context.info.VendorPrototypeConfigCommands)),
					configRequirement("6.11.3", "vendor-prototype-only-if-command-list-present", "#vendorPrototype", RequirementConstraint),
				)

				return results
			},
		},
	}
}
