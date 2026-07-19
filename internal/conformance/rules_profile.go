package conformance

import (
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
)

func profileRules() []getInfoRule {
	stableProfile := func(context *getInfoContext) bool {
		return context.target.Profile == model.ProfileFIDO21 || context.target.Profile == model.ProfileFIDO23
	}

	return []getInfoRule{
		{
			id:       model.RuleProfileHMACSecretRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "1", "hmac-secret-required")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if slices.Contains(context.info.Extensions, extension.ExtensionIdentifierHMACSecret) {
					return nil
				}

				return finding(
					[]model.FieldPath{"extensions.hmac-secret"},
					expected(model.ExpectationContains, "hmac-secret"),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       model.RuleProfileRKUVCapabilityRequired,
			selector: selectFIDO21,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "2", "rk-requires-configured-user-verification")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionResidentKeys) ||
					optionTrue(context.info, protocol.OptionClientPIN) ||
					optionTrue(context.info, protocol.OptionUserVerification) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.clientPin", "options.uv"},
					expectedAny(model.ExpectationTrue),
					observedOption(context.info, protocol.OptionResidentKeys),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
				)
			},
		},
		{
			id:       model.RuleProfileRKUVCapabilityRequired,
			selector: selectFIDO23,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "2", "rk-requires-user-verification-capability-state")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionResidentKeys) ||
					optionPresent(context.info, protocol.OptionClientPIN) ||
					optionPresent(context.info, protocol.OptionUserVerification) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.clientPin", "options.uv"},
					expectedAny(model.ExpectationRequired),
					observedOption(context.info, protocol.OptionResidentKeys),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
				)
			},
		},
		{
			id:       model.RuleProfileRKCredentialManagementRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "3", "rk-requires-credential-inventory")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionResidentKeys) || optionTrue(context.info, protocol.OptionCredentialManagement) {
					return nil
				}

				return inconclusive(
					[]model.FieldPath{"options.credMgmt"},
					expected(model.ExpectationTrue),
					model.EvidenceGapAuthenticatorUIUnknown,
					observedOption(context.info, protocol.OptionResidentKeys),
					observedOption(context.info, protocol.OptionCredentialManagement),
				)
			},
		},
		{
			id:       model.RuleProfileCredentialProtectionRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "4", "user-verification-requires-cred-protect")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				uvSupported := optionPresent(context.info, protocol.OptionClientPIN) || optionPresent(context.info, protocol.OptionUserVerification)
				if !uvSupported || slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
					return nil
				}

				return inconclusive(
					[]model.FieldPath{"extensions.credProtect"},
					expected(model.ExpectationContains, "credProtect"),
					model.EvidenceGapImplicitCredProtectUnknown,
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       model.RuleProfilePinUVAuthTokenRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "5", "configured-user-verification-requires-pin-uv-auth-token")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				uvConfigured := optionTrue(context.info, protocol.OptionClientPIN) || optionTrue(context.info, protocol.OptionUserVerification)
				if !uvConfigured || optionTrue(context.info, protocol.OptionPinUvAuthToken) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.pinUvAuthToken"},
					expected(model.ExpectationTrue),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
					observedOption(context.info, protocol.OptionPinUvAuthToken),
				)
			},
		},
		{
			id:       model.RuleProfilePinUVProtocolTwoRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{mandatoryRequirement(context.target, "6", "pin-uv-auth-protocol-two-required")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if len(context.info.PinUvAuthProtocols) == 0 || slices.Contains(context.info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
					return nil
				}

				return finding(
					[]model.FieldPath{"pinUvAuthProtocols"},
					expected(model.ExpectationContains, "2"),
					observedStrings("pinUvAuthProtocols", true, pinProtocolValues(context.info)),
				)
			},
		},
	}
}
