package conformance

import (
	"slices"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
)

func profileRules() []getInfoRule {
	stableProfile := func(context *getInfoContext) bool {
		return context.target.Profile == ProfileFIDO21 || context.target.Profile == ProfileFIDO23
	}

	return []getInfoRule{
		{
			id:       RuleProfileHMACSecretRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "1", "hmac-secret-required")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if slices.Contains(context.info.Extensions, extension.ExtensionIdentifierHMACSecret) {
					return nil
				}

				return finding(
					[]FieldPath{"extensions.hmac-secret"},
					expected(ExpectationContains, "hmac-secret"),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       RuleProfileRKUVCapabilityRequired,
			selector: selectFIDO21,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "2", "rk-requires-configured-user-verification")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionResidentKeys) ||
					optionTrue(context.info, protocol.OptionClientPIN) ||
					optionTrue(context.info, protocol.OptionUserVerification) {
					return nil
				}

				return finding(
					[]FieldPath{"options.clientPin", "options.uv"},
					expectedAny(ExpectationTrue),
					observedOption(context.info, protocol.OptionResidentKeys),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
				)
			},
		},
		{
			id:       RuleProfileRKUVCapabilityRequired,
			selector: selectFIDO23,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "2", "rk-requires-user-verification-capability-state")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionResidentKeys) ||
					optionPresent(context.info, protocol.OptionClientPIN) ||
					optionPresent(context.info, protocol.OptionUserVerification) {
					return nil
				}

				return finding(
					[]FieldPath{"options.clientPin", "options.uv"},
					expectedAny(ExpectationRequired),
					observedOption(context.info, protocol.OptionResidentKeys),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
				)
			},
		},
		{
			id:       RuleProfileRKCredentialManagementRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "3", "rk-requires-credential-inventory")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionResidentKeys) || optionTrue(context.info, protocol.OptionCredentialManagement) {
					return nil
				}

				return inconclusive(
					[]FieldPath{"options.credMgmt"},
					expected(ExpectationTrue),
					EvidenceGapAuthenticatorUIUnknown,
					observedOption(context.info, protocol.OptionResidentKeys),
					observedOption(context.info, protocol.OptionCredentialManagement),
				)
			},
		},
		{
			id:       RuleProfileCredentialProtectionRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "4", "user-verification-requires-cred-protect")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				uvSupported := optionPresent(context.info, protocol.OptionClientPIN) || optionPresent(context.info, protocol.OptionUserVerification)
				if !uvSupported || slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
					return nil
				}

				return inconclusive(
					[]FieldPath{"extensions.credProtect"},
					expected(ExpectationContains, "credProtect"),
					EvidenceGapImplicitCredProtectUnknown,
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       RuleProfilePinUVAuthTokenRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "5", "configured-user-verification-requires-pin-uv-auth-token")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				uvConfigured := optionTrue(context.info, protocol.OptionClientPIN) || optionTrue(context.info, protocol.OptionUserVerification)
				if !uvConfigured || optionTrue(context.info, protocol.OptionPinUvAuthToken) {
					return nil
				}

				return finding(
					[]FieldPath{"options.pinUvAuthToken"},
					expected(ExpectationTrue),
					observedOption(context.info, protocol.OptionClientPIN),
					observedOption(context.info, protocol.OptionUserVerification),
					observedOption(context.info, protocol.OptionPinUvAuthToken),
				)
			},
		},
		{
			id:       RuleProfilePinUVProtocolTwoRequired,
			selector: stableProfile,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{mandatoryRequirement(context.target, "6", "pin-uv-auth-protocol-two-required")}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if len(context.info.PinUvAuthProtocols) == 0 || slices.Contains(context.info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
					return nil
				}

				return finding(
					[]FieldPath{"pinUvAuthProtocols"},
					expected(ExpectationContains, "2"),
					observedStrings("pinUvAuthProtocols", true, pinProtocolValues(context.info)),
				)
			},
		},
	}
}
