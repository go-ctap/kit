package conformance

import (
	"slices"
	"strconv"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
)

func blobRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       RuleCredBlobRequiresCredProtect,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(context.target, "12.2.1", "cred-blob-requires-cred-protect", "#sctn-credBlob-extension", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				credBlob := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialBlob)
				credProtect := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialProtection)
				if !credBlob || credProtect {
					return nil
				}

				return finding(
					[]FieldPath{"extensions.credProtect"},
					expected(ExpectationContains, "credProtect"),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       RuleCredBlobRequiresMaxLength,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "cred-blob-requires-max-length", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialBlob) || context.info.MaxCredBlobLength != nil {
					return nil
				}

				return finding(
					[]FieldPath{"maxCredBlobLength"},
					expected(ExpectationRequired),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observed("maxCredBlobLength", EvidenceAbsent),
				)
			},
		},
		{
			id:       RuleCredBlobMaxLengthMinimum,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "cred-blob-max-length-minimum", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxCredBlobLength == nil || *context.info.MaxCredBlobLength >= 32 {
					return nil
				}

				return finding(
					[]FieldPath{"maxCredBlobLength"},
					expected(ExpectationMinimum, "32"),
					observedUnsigned("maxCredBlobLength", *context.info.MaxCredBlobLength),
				)
			},
		},
		{
			id:       RuleCredBlobMaxLengthRequiresExtension,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "cred-blob-max-length-requires-extension", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxCredBlobLength == nil || slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialBlob) {
					return nil
				}

				return finding(
					[]FieldPath{"maxCredBlobLength"},
					expected(ExpectationAbsent),
					observedUnsigned("maxCredBlobLength", *context.info.MaxCredBlobLength),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       RuleLargeBlobModesMutuallyExclusive,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "large-blob-modes-mutually-exclusive", RequirementMustNot)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				legacy := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlob)
				if !legacy || !optionTrue(context.info, protocol.OptionLargeBlobs) {
					return nil
				}

				return finding(
					[]FieldPath{"extensions.largeBlob", "options.largeBlobs"},
					expected(ExpectationNotBoth),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observedOption(context.info, protocol.OptionLargeBlobs),
				)
			},
		},
		{
			id:       RuleLargeBlobExtensionsMutuallyExclusive,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(context.target, "12.4", "large-blob-extensions-mutually-exclusive", "#sctn-largeBlob-extension", RequirementMustNot)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				legacy := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlob)
				key := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
				if !legacy || !key {
					return nil
				}

				return finding(
					[]FieldPath{"extensions.largeBlob", "extensions.largeBlobKey"},
					expected(ExpectationNotBoth),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       RuleLargeBlobKeyRequiresCommand,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{featureRequirement(context.target, "6.10.1", "large-blob-key-requires-large-blobs-command", "#largeBlobsFeatureDetection", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				key := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
				if !key || optionTrue(context.info, protocol.OptionLargeBlobs) {
					return nil
				}

				return finding(
					[]FieldPath{"options.largeBlobs"},
					expected(ExpectationTrue),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observedOption(context.info, protocol.OptionLargeBlobs),
				)
			},
		},
		{
			id:       RuleLargeBlobsRequiresCapacity,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "large-blobs-command-requires-capacity", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionLargeBlobs) || context.info.MaxSerializedLargeBlobArray != nil {
					return nil
				}

				return finding(
					[]FieldPath{"maxSerializedLargeBlobArray"},
					expected(ExpectationRequired),
					observedOption(context.info, protocol.OptionLargeBlobs),
					observed("maxSerializedLargeBlobArray", EvidenceAbsent),
				)
			},
		},
		{
			id:       RuleLargeBlobsCapacityMinimum,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "large-blobs-capacity-minimum", RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				value := context.info.MaxSerializedLargeBlobArray
				if value == nil || *value >= 1024 {
					return nil
				}

				return finding(
					[]FieldPath{"maxSerializedLargeBlobArray"},
					expected(ExpectationMinimum, "1024"),
					observed("maxSerializedLargeBlobArray", EvidenceValue, strconv.FormatUint(uint64(*value), 10)),
				)
			},
		},
		{
			id:       RuleLargeBlobsCapacityRequiresCommand,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []RequirementRef {
				return []RequirementRef{getInfoRequirement(context.target, "large-blobs-capacity-requires-command", RequirementMustNot)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				value := context.info.MaxSerializedLargeBlobArray
				if value == nil || optionTrue(context.info, protocol.OptionLargeBlobs) {
					return nil
				}

				return finding(
					[]FieldPath{"maxSerializedLargeBlobArray"},
					expected(ExpectationAbsent),
					observedUnsigned("maxSerializedLargeBlobArray", *value),
					observedOption(context.info, protocol.OptionLargeBlobs),
				)
			},
		},
	}
}
