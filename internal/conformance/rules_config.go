package conformance

import (
	"slices"

	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
)

func configRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       model.RuleAuthenticatorConfigSupportConsistency,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				references := []model.RequirementRef{
					getInfoRequirement(context.target, "authnr-cfg-true-means-authenticator-config-supported", model.RequirementConstraint),
				}

				if context.target.Specification == model.SpecificationCTAP23 {
					references = append(references, getInfoRequirement(context.target, "authenticator-config-commands-indicate-command-support", model.RequirementConstraint))
				}

				return references
			},
			evaluate: func(context *getInfoContext) []assessment {
				supportExpected := context.commandsKnown ||
					setMinSupportExpected(context) ||
					context.info.VendorPrototypeConfigCommands != nil ||
					(context.target.Profile == model.ProfileFIDO23 && optionPresent(context.info, protocol.OptionEnterpriseAttestation))
				if !supportExpected || optionTrue(context.info, protocol.OptionAuthenticatorConfig) {
					return nil
				}

				evidence := []model.Evidence{
					observedOption(context.info, protocol.OptionAuthenticatorConfig),
					observedOption(context.info, protocol.OptionSetMinPINLength),
					observedOption(context.info, protocol.OptionEnterpriseAttestation),
					observedStrings("vendorPrototypeConfigCommands", context.info.VendorPrototypeConfigCommands != nil, unsignedValues(context.info.VendorPrototypeConfigCommands)),
				}

				if context.target.Specification == model.SpecificationCTAP23 {
					evidence = append(evidence, observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands)))
				}

				return finding(
					[]model.FieldPath{"options.authnrCfg"},
					expected(model.ExpectationTrue),
					evidence...,
				)
			},
		},
		{
			id:       model.RuleConfigCommandRequired,
			selector: selectCTAP23Document,
			references: func(*getInfoContext) []model.RequirementRef {
				return nil
			},
			evaluate: func(context *getInfoContext) []assessment {
				results := make([]assessment, 0, 2)
				commands := observedStrings("authenticatorConfigCommands", context.commandsKnown, unsignedValues(context.info.AuthenticatorConfigCommands))

				if context.target.Profile == model.ProfileFIDO23 &&
					optionPresent(context.info, protocol.OptionEnterpriseAttestation) &&
					!slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandEnableEnterpriseAttestation) {
					results = append(results, findingWithReferences(
						[]model.FieldPath{"authenticatorConfigCommands"},
						expected(model.ExpectationContains, "0x01"),
						[]model.Evidence{observedOption(context.info, protocol.OptionEnterpriseAttestation), commands},
						mandatoryRequirement(context.target, "8", "enterprise-attestation-requires-config-subcommand"),
						configRequirement("6.11.1", "enable-enterprise-attestation-must-be-in-inventory", "#enableEnterpriseAttestation", model.RequirementMust),
					))
				}

				if context.info.VendorPrototypeConfigCommands != nil &&
					!slices.Contains(context.info.AuthenticatorConfigCommands, protocol.ConfigSubCommandVendorPrototype) {
					results = append(results, findingWithReferences(
						[]model.FieldPath{"authenticatorConfigCommands"},
						expected(model.ExpectationContains, "0xFF"),
						[]model.Evidence{
							observedStrings("vendorPrototypeConfigCommands", true, unsignedValues(context.info.VendorPrototypeConfigCommands)),
							commands,
						},
						requirement(model.SpecificationCTAP23, "6.4", "vendor-prototype-command-list-means-subcommand-supported", ctap23URL+"#authenticatorGetInfo", model.RequirementConstraint),
						configRequirement("6.11.3", "vendor-prototype-must-be-in-inventory", "#vendorPrototype", model.RequirementMust),
					))
				}

				return results
			},
		},
		{
			id:       model.RuleConfigCommandPrerequisite,
			selector: selectCommandsKnown,
			references: func(*getInfoContext) []model.RequirementRef {
				return nil
			},
			evaluate: func(context *getInfoContext) []assessment {
				commands := observedStrings("authenticatorConfigCommands", true, unsignedValues(context.info.AuthenticatorConfigCommands))
				results := make([]assessment, 0, 4)
				add := func(command protocol.ConfigSubCommand, valid bool, subject model.FieldPath, expectation model.Expectation, evidence model.Evidence, reference model.RequirementRef) {
					if !slices.Contains(context.info.AuthenticatorConfigCommands, command) || valid {
						return
					}
					results = append(results, findingWithReferences(
						[]model.FieldPath{subject},
						expectation,
						[]model.Evidence{evidence, commands},
						reference,
					))
				}

				add(
					protocol.ConfigSubCommandEnableEnterpriseAttestation,
					optionPresent(context.info, protocol.OptionEnterpriseAttestation),
					"options.ep",
					expected(model.ExpectationRequired),
					observedOption(context.info, protocol.OptionEnterpriseAttestation),
					configRequirement("6.11.1", "enable-enterprise-attestation-only-if-feature-supported", "#enableEnterpriseAttestation", model.RequirementConstraint),
				)
				add(
					protocol.ConfigSubCommandToggleAlwaysUv,
					optionPresent(context.info, protocol.OptionAlwaysUv),
					"options.alwaysUv",
					expected(model.ExpectationRequired),
					observedOption(context.info, protocol.OptionAlwaysUv),
					configRequirement("6.11.2", "toggle-always-uv-only-if-feature-supported", "#toggleAlwaysUv", model.RequirementConstraint),
				)

				longTouchState := model.EvidenceAbsent
				if context.info.LongTouchForReset != nil {
					longTouchState = model.EvidenceFalse
					if *context.info.LongTouchForReset {
						longTouchState = model.EvidenceTrue
					}
				}
				add(
					protocol.ConfigSubCommandEnableLongTouchForReset,
					context.info.LongTouchForReset != nil,
					"longTouchForReset",
					expected(model.ExpectationRequired),
					observed("longTouchForReset", longTouchState),
					configRequirement("6.11.5", "enable-long-touch-only-if-feature-supported", "#enableLongTouchForReset", model.RequirementConstraint),
				)
				add(
					protocol.ConfigSubCommandVendorPrototype,
					context.info.VendorPrototypeConfigCommands != nil,
					"vendorPrototypeConfigCommands",
					expected(model.ExpectationRequired),
					observedStrings("vendorPrototypeConfigCommands", context.info.VendorPrototypeConfigCommands != nil, unsignedValues(context.info.VendorPrototypeConfigCommands)),
					configRequirement("6.11.3", "vendor-prototype-only-if-command-list-present", "#vendorPrototype", model.RequirementConstraint),
				)

				return results
			},
		},
	}
}
