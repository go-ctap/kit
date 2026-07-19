package conformance

import (
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
	"github.com/samber/lo"
)

func optionDependencyRules() []getInfoRule {
	return []getInfoRule{
		optionPlacementRule(
			model.RuleNoMCGARequiresClientPIN,
			protocol.OptionNoMcGaPermissionsWithClientPin,
			protocol.OptionClientPIN,
			"no-mc-ga-permissions-requires-client-pin",
		),
		optionPlacementRule(
			model.RuleUVBioEnrollRequiresBioEnroll,
			protocol.OptionUvBioEnroll,
			protocol.OptionBioEnroll,
			"uv-bio-enroll-requires-bio-enroll",
		),
		optionPlacementRule(
			model.RuleUVAcfgRequiresAuthnrCfg,
			protocol.OptionUvAcfg,
			protocol.OptionAuthenticatorConfig,
			"uv-acfg-requires-authnr-cfg",
		),
		{
			id:       model.RuleAlwaysUVConflictsWithMakeCredUVNotRqd,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "always-uv-conflicts-with-make-cred-uv-not-required", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionAlwaysUv) || !optionTrue(context.info, protocol.OptionMakeCredentialUvNotRequired) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.alwaysUv", "options.makeCredUvNotRqd"},
					expected(model.ExpectationNotBoth),
					observedOption(context.info, protocol.OptionAlwaysUv),
					observedOption(context.info, protocol.OptionMakeCredentialUvNotRequired),
				)
			},
		},
		{
			id:       model.RuleAlwaysUVU2FRequiresBuiltInUV,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(
					context.target,
					"7.2.4",
					"always-uv-disabled-u2f-must-not-be-advertised",
					"#sctn-feature-descriptions-alwaysUv",
					model.RequirementMustNot,
				)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionAlwaysUv) ||
					!context.info.Versions.Supports(protocol.U2F_V2) ||
					optionTrue(context.info, protocol.OptionUserVerification) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.uv"},
					expected(model.ExpectationTrue),
					observedOption(context.info, protocol.OptionAlwaysUv),
					observedStrings("versions", true, lo.Map(
						context.info.Versions,
						func(version protocol.Version, _ int) string { return string(version) },
					)),
					observedOption(context.info, protocol.OptionUserVerification),
				)
			},
		},
	}
}

func optionPlacementRule(id model.RuleID, dependent, required protocol.Option, clause string) getInfoRule {
	return getInfoRule{
		id:       id,
		selector: selectCTAP21OrLater,
		references: func(context *getInfoContext) []model.RequirementRef {
			return []model.RequirementRef{getInfoRequirement(context.target, clause, model.RequirementMust)}
		},
		evaluate: func(context *getInfoContext) []assessment {
			if !optionPresent(context.info, dependent) || optionPresent(context.info, required) {
				return nil
			}

			return finding(
				[]model.FieldPath{model.FieldPath("options." + string(required))},
				expected(model.ExpectationRequired),
				observedOption(context.info, dependent),
				observedOption(context.info, required),
			)
		},
	}
}
