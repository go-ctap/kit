package conformance

import (
	"github.com/go-ctap/ctap/protocol"
	"github.com/samber/lo"
)

func optionDependencyRules() []getInfoRule {
	return []getInfoRule{
		optionPlacementRule(
			RuleNoMCGARequiresClientPIN,
			protocol.OptionNoMcGaPermissionsWithClientPin,
			protocol.OptionClientPIN,
			"no-mc-ga-permissions-requires-client-pin",
		),
		optionPlacementRule(
			RuleUVBioEnrollRequiresBioEnroll,
			protocol.OptionUvBioEnroll,
			protocol.OptionBioEnroll,
			"uv-bio-enroll-requires-bio-enroll",
		),
		optionPlacementRule(
			RuleUVAcfgRequiresAuthnrCfg,
			protocol.OptionUvAcfg,
			protocol.OptionAuthenticatorConfig,
			"uv-acfg-requires-authnr-cfg",
		),
		{
			id:       RuleAlwaysUVConflictsWithMakeCredUVNotRqd,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "always-uv-conflicts-with-make-cred-uv-not-required", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionAlwaysUv) || !optionTrue(context.info, protocol.OptionMakeCredentialUvNotRequired) {
					return nil
				}

				return finding(
					[]FieldPath{"options.alwaysUv", "options.makeCredUvNotRqd"},
					expected(ExpectationNotBoth),
					observedOption(context.info, protocol.OptionAlwaysUv),
					observedOption(context.info, protocol.OptionMakeCredentialUvNotRequired),
				)
			},
		},
		{
			id:       RuleAlwaysUVU2FRequiresBuiltInUV,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(
					context.target,
					"7.2.4",
					"always-uv-disabled-u2f-must-not-be-advertised",
					"#sctn-feature-descriptions-alwaysUv",
					RequirementMustNot,
				)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionAlwaysUv) ||
					!context.info.Versions.Supports(protocol.U2F_V2) ||
					optionTrue(context.info, protocol.OptionUserVerification) {
					return nil
				}

				return finding(
					[]FieldPath{"options.uv"},
					expected(ExpectationTrue),
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

func optionPlacementRule(id RuleID, dependent, required protocol.Option, clause string) getInfoRule {
	return getInfoRule{
		id:       id,
		selector: selectCTAP21OrLater,
		references: func(context *getInfoContext) []RequirementRef {
			return []RequirementRef{getInfoRequirement(context.target, clause, RequirementMust)}
		},
		evaluate: func(context *getInfoContext) []assessment {
			if !optionPresent(context.info, dependent) || optionPresent(context.info, required) {
				return nil
			}

			return finding(
				[]FieldPath{FieldPath("options." + string(required))},
				expected(ExpectationRequired),
				observedOption(context.info, dependent),
				observedOption(context.info, required),
			)
		},
	}
}
