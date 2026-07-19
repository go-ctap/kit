package conformance

import (
	"slices"
	"strconv"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
)

func blobRules() []getInfoRule {
	return []getInfoRule{
		{
			id:       model.RuleCredBlobRequiresCredProtect,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(context.target, "12.2.1", "cred-blob-requires-cred-protect", "#sctn-credBlob-extension", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				credBlob := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialBlob)
				credProtect := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialProtection)
				if !credBlob || credProtect {
					return nil
				}

				return finding(
					[]model.FieldPath{"extensions.credProtect"},
					expected(model.ExpectationContains, "credProtect"),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       model.RuleCredBlobRequiresMaxLength,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "cred-blob-requires-max-length", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialBlob) || context.info.MaxCredBlobLength != 0 {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxCredBlobLength"},
					expected(model.ExpectationRequired),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observed("maxCredBlobLength", model.EvidenceAbsent),
				)
			},
		},
		{
			id:       model.RuleCredBlobMaxLengthMinimum,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "cred-blob-max-length-minimum", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxCredBlobLength == 0 || context.info.MaxCredBlobLength >= 32 {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxCredBlobLength"},
					expected(model.ExpectationMinimum, "32"),
					observedUnsigned("maxCredBlobLength", context.info.MaxCredBlobLength),
				)
			},
		},
		{
			id:       model.RuleCredBlobMaxLengthRequiresExtension,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "cred-blob-max-length-requires-extension", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if context.info.MaxCredBlobLength == 0 || slices.Contains(context.info.Extensions, extension.ExtensionIdentifierCredentialBlob) {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxCredBlobLength"},
					expected(model.ExpectationAbsent),
					observedUnsigned("maxCredBlobLength", context.info.MaxCredBlobLength),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       model.RuleLargeBlobModesMutuallyExclusive,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "large-blob-modes-mutually-exclusive", model.RequirementMustNot)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				legacy := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlob)
				if !legacy || !optionTrue(context.info, protocol.OptionLargeBlobs) {
					return nil
				}

				return finding(
					[]model.FieldPath{"extensions.largeBlob", "options.largeBlobs"},
					expected(model.ExpectationNotBoth),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observedOption(context.info, protocol.OptionLargeBlobs),
				)
			},
		},
		{
			id:       model.RuleLargeBlobExtensionsMutuallyExclusive,
			selector: selectCTAP23Document,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(context.target, "12.4", "large-blob-extensions-mutually-exclusive", "#sctn-largeBlob-extension", model.RequirementMustNot)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				legacy := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlob)
				key := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
				if !legacy || !key {
					return nil
				}

				return finding(
					[]model.FieldPath{"extensions.largeBlob", "extensions.largeBlobKey"},
					expected(model.ExpectationNotBoth),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
				)
			},
		},
		{
			id:       model.RuleLargeBlobKeyRequiresCommand,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{featureRequirement(context.target, "6.10.1", "large-blob-key-requires-large-blobs-command", "#largeBlobsFeatureDetection", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				key := slices.Contains(context.info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
				if !key || optionTrue(context.info, protocol.OptionLargeBlobs) {
					return nil
				}

				return finding(
					[]model.FieldPath{"options.largeBlobs"},
					expected(model.ExpectationTrue),
					observedStrings("extensions", context.info.Extensions != nil, extensionValues(context.info)),
					observedOption(context.info, protocol.OptionLargeBlobs),
				)
			},
		},
		{
			id:       model.RuleLargeBlobsRequiresCapacity,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "large-blobs-command-requires-capacity", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				if !optionTrue(context.info, protocol.OptionLargeBlobs) || context.info.MaxSerializedLargeBlobArray != 0 {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxSerializedLargeBlobArray"},
					expected(model.ExpectationRequired),
					observedOption(context.info, protocol.OptionLargeBlobs),
					observed("maxSerializedLargeBlobArray", model.EvidenceAbsent),
				)
			},
		},
		{
			id:       model.RuleLargeBlobsCapacityMinimum,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "large-blobs-capacity-minimum", model.RequirementMust)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				value := context.info.MaxSerializedLargeBlobArray
				if value == 0 || value >= 1024 {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxSerializedLargeBlobArray"},
					expected(model.ExpectationMinimum, "1024"),
					observed("maxSerializedLargeBlobArray", model.EvidenceValue, strconv.FormatUint(uint64(value), 10)),
				)
			},
		},
		{
			id:       model.RuleLargeBlobsCapacityRequiresCommand,
			selector: selectCTAP21OrLater,
			references: func(context *getInfoContext) []model.RequirementRef {
				return []model.RequirementRef{getInfoRequirement(context.target, "large-blobs-capacity-requires-command", model.RequirementMustNot)}
			},
			evaluate: func(context *getInfoContext) []assessment {
				value := context.info.MaxSerializedLargeBlobArray
				if value == 0 || optionTrue(context.info, protocol.OptionLargeBlobs) {
					return nil
				}

				return finding(
					[]model.FieldPath{"maxSerializedLargeBlobArray"},
					expected(model.ExpectationAbsent),
					observedUnsigned("maxSerializedLargeBlobArray", value),
					observedOption(context.info, protocol.OptionLargeBlobs),
				)
			},
		},
	}
}
