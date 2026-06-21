package conformance

import (
	"fmt"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	"github.com/samber/lo"
)

// EvaluateGetInfo returns reusable CTAP/FIDO conformance findings for an
// authenticatorGetInfo response. It intentionally contains no product copy,
// localization, grouping, or presentation policy.
func EvaluateGetInfo(info protocol.AuthenticatorGetInfoResponse) []Finding {
	findings := make([]Finding, 0)
	add := func(id FindingID, source string, value FindingValue, args map[string]any) {
		finding := Finding{ID: id, Source: source, Value: value}
		if len(args) > 0 {
			finding.Args = args
		}
		findings = append(findings, finding)
	}

	if len(info.Versions) == 0 {
		add(FindingVersionsRequired, "versions", CommonValue(CommonValueNotReported), map[string]any{"field": "versions"})
	}

	if lo.Contains(info.Versions, protocol.Version("FIDO_2_2")) {
		add(FindingFIDO22Forbidden, "versions", LiteralValue("FIDO_2_2"), map[string]any{"field": "versions", "version": "FIDO_2_2"})
	}

	if info.PinUvAuthProtocols != nil {
		findings = validateNonEmptyUniqueList(findings, "pinUvAuthProtocols", info.PinUvAuthProtocols, FindingPinUVAuthProtocolsListEmpty, FindingPinUVAuthProtocolsListDuplicate, pinUVAuthProtocolKey)
	}
	if info.Transports != nil {
		findings = validateNonEmptyUniqueList(findings, "transports", info.Transports, FindingTransportsListEmpty, FindingTransportsListDuplicate, stringKey)
	}
	if info.Algorithms != nil {
		findings = validateNonEmptyUniqueList(findings, "algorithms", info.Algorithms, FindingAlgorithmsListEmpty, FindingAlgorithmsListDuplicate, algorithmKey)
	}
	if info.TransportsForReset != nil {
		findings = validateNonEmptyUniqueList(findings, "transportsForReset", info.TransportsForReset, FindingTransportsForResetListEmpty, FindingTransportsForResetListDuplicate, stringKey)
	}
	if info.AttestationFormats != nil {
		findings = validateNonEmptyUniqueList(findings, "attestationFormats", info.AttestationFormats, FindingAttestationFormatsListEmpty, FindingAttestationFormatsListDuplicate, stringKey)
	}

	if info.MaxCredentialCountInList != nil && *info.MaxCredentialCountInList == 0 {
		add(FindingMaxCredentialCountInListPositive, "maxCredentialCountInList", InputValue(*info.MaxCredentialCountInList), map[string]any{"field": "maxCredentialCountInList", "minimum": 1})
	}
	if info.MaxCredentialIdLength != nil && *info.MaxCredentialIdLength == 0 {
		add(FindingMaxCredentialIDLengthPositive, "maxCredentialIdLength", InputValue(*info.MaxCredentialIdLength), map[string]any{"field": "maxCredentialIdLength", "minimum": 1})
	}
	if info.MaxMsgSize != nil && *info.MaxMsgSize < 1024 {
		add(FindingMaxMsgSizeMinimum, "maxMsgSize", InputValue(*info.MaxMsgSize), map[string]any{"field": "maxMsgSize", "minimum": 1024})
	}
	if info.PreferredPlatformUvAttempts != nil && *info.PreferredPlatformUvAttempts < 1 {
		add(FindingPreferredPlatformUVAttemptsMinimum, "preferredPlatformUvAttempts", InputValue(*info.PreferredPlatformUvAttempts), map[string]any{"field": "preferredPlatformUvAttempts", "minimum": 1})
	}

	extensionsKnown := info.Extensions != nil
	pinUVAuthProtocolsKnown := info.PinUvAuthProtocols != nil
	isCTAP23 := lo.Contains(info.Versions, protocol.FIDO_2_3)
	clientPINSupported := lo.HasKey(info.Options, protocol.OptionClientPIN)
	uvSupported := lo.HasKey(info.Options, protocol.OptionUserVerification)
	largeBlobsCommand := optionTrue(info.Options, protocol.OptionLargeBlobs)
	credBlobListed := lo.Contains(info.Extensions, extension.ExtensionIdentifierCredentialBlob)
	setMinPINLengthPresent := lo.HasKey(info.Options, protocol.OptionSetMinPINLength)
	setMinPINLength := optionTrue(info.Options, protocol.OptionSetMinPINLength)
	setMinPINLengthCommand := lo.Contains(info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandSetMinPINLength))
	setMinPINLengthSupported := setMinPINLength || setMinPINLengthCommand
	pinComplexityListed := lo.Contains(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)

	if lo.Contains(info.AttestationFormats, "none") {
		add(FindingAttestationFormatsNone, "attestationFormats", LiteralValue("none"), map[string]any{"field": "attestationFormats", "format": "none"})
	}

	if isCTAP23 && (!extensionsKnown || !lo.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret)) {
		add(FindingCTAP23HMACSecret, "extensions.hmac-secret", CommonValue(CommonValueNotListed), map[string]any{"extension": "hmac-secret"})
	}

	if isCTAP23 && optionTrue(info.Options, protocol.OptionResidentKeys) {
		if !clientPINSupported && !uvSupported {
			add(FindingCTAP23RKUVState, "options.rk + options.clientPin/options.uv", LiteralValue("options.rk"), map[string]any{"option": "rk"})
		}
	}

	if isCTAP23 && (optionTrue(info.Options, protocol.OptionClientPIN) || optionTrue(info.Options, protocol.OptionUserVerification)) && !optionTrue(info.Options, protocol.OptionPinUvAuthToken) {
		add(FindingCTAP23PinUVAuthToken, "options.pinUvAuthToken", LiteralValue("options.pinUvAuthToken"), map[string]any{"option": "pinUvAuthToken"})
	}

	if isCTAP23 && pinUVAuthProtocolsKnown && len(info.PinUvAuthProtocols) > 0 && !lo.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		add(FindingCTAP23PinProtocolTwo, "pinUvAuthProtocols", ListValue(lo.Map(info.PinUvAuthProtocols, func(item protocol.PinUvAuthProtocol, _ int) any {
			return item
		})), map[string]any{"field": "pinUvAuthProtocols", "protocol": 2})
	}

	if credBlobListed && !lo.Contains(info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
		add(FindingCredBlobRequiresCredProtect, "extensions.credBlob + extensions.credProtect", LiteralValue("credProtect"), map[string]any{"extension": "credProtect"})
	}

	if credBlobListed && info.MaxCredBlobLength == nil {
		add(FindingCredBlobRequiresLimit, "maxCredBlobLength", CommonValue(CommonValueNotReported), map[string]any{"field": "maxCredBlobLength"})
	}

	if info.MaxCredBlobLength != nil {
		if *info.MaxCredBlobLength < 32 {
			add(FindingCredBlobLimitInvalid, "maxCredBlobLength", InputValue(*info.MaxCredBlobLength), map[string]any{"field": "maxCredBlobLength", "minimum": 32})
		}
		if !credBlobListed {
			add(FindingCredBlobLimitWithoutExtension, "maxCredBlobLength + extensions.credBlob", InputValue(*info.MaxCredBlobLength), map[string]any{"field": "maxCredBlobLength", "extension": "credBlob"})
		}
	}

	largeBlobListed := lo.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlob)
	largeBlobKeyListed := lo.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
	if largeBlobListed && largeBlobsCommand {
		add(FindingLargeBlobModeConflict, "extensions.largeBlob + options.largeBlobs", CommonValue(CommonValueMutuallyExclusiveSupportReported), map[string]any{"extension": "largeBlob", "option": "largeBlobs"})
	}

	if largeBlobListed && largeBlobKeyListed {
		add(FindingLargeBlobExtensionsConflict, "extensions.largeBlob + extensions.largeBlobKey", CommonValue(CommonValueMutuallyExclusiveSupportReported), map[string]any{"extension": "largeBlobKey"})
	}

	if largeBlobKeyListed && !largeBlobsCommand {
		add(FindingLargeBlobKeyIncomplete, "extensions.largeBlobKey + options.largeBlobs", CommonValue(CommonValueExtensionReportedCommandMissing), map[string]any{"extension": "largeBlobKey", "option": "largeBlobs"})
	}

	if largeBlobsCommand && info.MaxSerializedLargeBlobArray == nil {
		add(FindingLargeBlobsRequiresLimit, "maxSerializedLargeBlobArray", CommonValue(CommonValueNotReported), map[string]any{"field": "maxSerializedLargeBlobArray"})
	}

	if info.MaxSerializedLargeBlobArray != nil {
		if *info.MaxSerializedLargeBlobArray < 1024 {
			add(FindingLargeBlobsLimitInvalid, "maxSerializedLargeBlobArray", InputValue(*info.MaxSerializedLargeBlobArray), map[string]any{"field": "maxSerializedLargeBlobArray", "minimum": 1024})
		}
		if !largeBlobsCommand {
			add(FindingLargeBlobsLimitWithoutCommand, "maxSerializedLargeBlobArray + options.largeBlobs", InputValue(*info.MaxSerializedLargeBlobArray), map[string]any{"field": "maxSerializedLargeBlobArray", "option": "largeBlobs"})
		}
	}

	minPinLengthListed := lo.Contains(info.Extensions, extension.ExtensionIdentifierMinPinLength)
	if minPinLengthListed && !setMinPINLengthCommand {
		add(FindingMinPINExtensionWithoutOption, "extensions.minPinLength + authenticatorConfigCommands", LiteralValue("0x03"), map[string]any{"extension": "minPinLength", "command": "setMinPINLength"})
	}

	if setMinPINLengthPresent && !clientPINSupported && !uvSupported {
		add(FindingSetMinPINWithoutUV, "options.setMinPINLength + options.clientPin/options.uv", LiteralValue("setMinPINLength"), map[string]any{"option": "setMinPINLength"})
	}

	if setMinPINLength {
		if !minPinLengthListed {
			add(FindingSetMinPINWithoutExtension, "options.setMinPINLength + extensions.minPinLength", LiteralValue("minPinLength"), map[string]any{"extension": "minPinLength", "option": "setMinPINLength"})
		}
		if !setMinPINLengthCommand {
			add(FindingSetMinPINCommandMissing, "authenticatorConfigCommands", LiteralValue("0x03"), map[string]any{"command": "setMinPINLength"})
		}
	}

	if info.MaxRPIDsForSetMinPINLength != nil {
		if !setMinPINLengthSupported {
			add(FindingMaxRPIDsWithoutSetMinPIN, "maxRPIDsForSetMinPINLength + authenticatorConfigCommands", InputValue(*info.MaxRPIDsForSetMinPINLength), map[string]any{"field": "maxRPIDsForSetMinPINLength", "command": "setMinPINLength"})
		}
	} else if setMinPINLengthSupported {
		add(FindingMaxRPIDsMissingWithSetMinPIN, "maxRPIDsForSetMinPINLength + authenticatorConfigCommands", CommonValue(CommonValueNotReported), map[string]any{"field": "maxRPIDsForSetMinPINLength", "command": "setMinPINLength"})
	}

	if info.MinPINLength != nil {
		if *info.MinPINLength < 4 {
			add(FindingMinPINLengthInvalid, "minPINLength", InputValue(*info.MinPINLength), map[string]any{"field": "minPINLength", "minimum": 4})
		}
		if !clientPINSupported {
			add(FindingMinPINWithoutClientPIN, "minPINLength + options.clientPin", InputValue(*info.MinPINLength), map[string]any{"field": "minPINLength", "option": "clientPin"})
		}
	} else if clientPINSupported {
		add(FindingMinPINMissing, "minPINLength + options.clientPin", CommonValue(CommonValueNotReported), map[string]any{"field": "minPINLength", "option": "clientPin"})
	}

	if info.MaxPINLength != nil {
		if *info.MaxPINLength < 8 {
			add(FindingMaxPINLengthInvalid, "maxPINLength", InputValue(*info.MaxPINLength), map[string]any{"field": "maxPINLength", "minimum": 8})
		}
		if !clientPINSupported {
			add(FindingMaxPINWithoutClientPIN, "maxPINLength + options.clientPin", InputValue(*info.MaxPINLength), map[string]any{"field": "maxPINLength", "option": "clientPin"})
		}
	}

	if pinComplexityListed && !setMinPINLengthCommand {
		add(FindingPinComplexityExtensionWithoutSetPIN, "extensions.pinComplexityPolicy + authenticatorConfigCommands", LiteralValue("0x03"), map[string]any{"extension": "pinComplexityPolicy", "command": "setMinPINLength"})
	}

	if (pinComplexityListed || info.PinComplexityPolicy != nil) && !clientPINSupported {
		value := LiteralValue("pinComplexityPolicy")
		if info.PinComplexityPolicy != nil {
			value = InputValue(*info.PinComplexityPolicy)
		}
		add(FindingPinComplexityWithoutClientPIN, "pinComplexityPolicy + options.clientPin", value, map[string]any{"field": "pinComplexityPolicy", "option": "clientPin"})
	}

	if lo.HasKey(info.Options, protocol.OptionNoMcGaPermissionsWithClientPin) && !lo.HasKey(info.Options, protocol.OptionClientPIN) {
		add(FindingNoMCGAWithoutClientPIN, "options.noMcGaPermissionsWithClientPin + options.clientPin", LiteralValue("noMcGaPermissionsWithClientPin"), map[string]any{"option": "clientPin"})
	}

	if lo.HasKey(info.Options, protocol.OptionUvBioEnroll) && !lo.HasKey(info.Options, protocol.OptionBioEnroll) {
		add(FindingUVBioEnrollWithoutBioEnroll, "options.uvBioEnroll + options.bioEnroll", LiteralValue("uvBioEnroll"), map[string]any{"option": "bioEnroll"})
	}

	if lo.HasKey(info.Options, protocol.OptionUvAcfg) && !lo.HasKey(info.Options, protocol.OptionAuthenticatorConfig) {
		add(FindingUVAcfgWithoutAuthnrCfg, "options.uvAcfg + options.authnrCfg", LiteralValue("uvAcfg"), map[string]any{"option": "authnrCfg"})
	}

	if info.AuthenticatorConfigCommands != nil && !optionTrue(info.Options, protocol.OptionAuthenticatorConfig) {
		add(FindingConfigCommandsWithoutAuthnrCfg, "authenticatorConfigCommands + options.authnrCfg", ListValue(lo.Map(info.AuthenticatorConfigCommands, func(item uint, _ int) any {
			return item
		})), map[string]any{"field": "authenticatorConfigCommands", "option": "authnrCfg"})
	}

	if optionTrue(info.Options, protocol.OptionAlwaysUv) && optionTrue(info.Options, protocol.OptionMakeCredentialUvNotRequired) {
		add(FindingAlwaysUVConflict, "options.alwaysUv + options.makeCredUvNotRqd", LiteralValue("alwaysUv + makeCredUvNotRqd"), map[string]any{"option": "alwaysUv"})
	}

	if lo.HasKey(info.Options, protocol.OptionAlwaysUv) && !lo.Contains(info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandToggleAlwaysUv)) {
		add(FindingAlwaysUVCommandMissing, "options.alwaysUv + authenticatorConfigCommands", LiteralValue("0x02"), map[string]any{"command": "toggleAlwaysUv"})
	}

	if lo.HasKey(info.Options, protocol.OptionEnterpriseAttestation) && !lo.Contains(info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandEnableEnterpriseAttestation)) {
		add(FindingEnterpriseAttestationCommandMissing, "options.ep + authenticatorConfigCommands", LiteralValue("0x01"), map[string]any{"command": "enableEnterpriseAttestation"})
	}

	if info.VendorPrototypeConfigCommands != nil && !lo.Contains(info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandVendorPrototype)) {
		add(FindingVendorPrototypeCommandMissing, "authenticatorConfigCommands + vendorPrototypeConfigCommands", LiteralValue("0xFF"), map[string]any{"command": "vendorPrototype"})
	}

	if info.LongTouchForReset != nil && !lo.Contains(info.AuthenticatorConfigCommands, uint(protocol.ConfigSubCommandEnableLongTouchForReset)) {
		add(FindingLongTouchCommandMissing, "authenticatorConfigCommands + longTouchForReset", LiteralValue("0x04"), map[string]any{"command": "enableLongTouchForReset"})
	}

	return findings
}

func validateNonEmptyUniqueList[T any](findings []Finding, source string, input []T, emptyID FindingID, duplicateID FindingID, key func(T) string) []Finding {
	if len(input) == 0 {
		return append(findings, Finding{
			ID:     emptyID,
			Source: source,
			Value:  CommonValue(CommonValueEmptyList),
			Args:   map[string]any{"field": source},
		})
	}

	if len(lo.FindDuplicatesBy(input, key)) > 0 {
		return append(findings, Finding{
			ID:     duplicateID,
			Source: source,
			Value: ListValue(lo.Map(input, func(item T, _ int) any {
				return item
			})),
			Args: map[string]any{"field": source},
		})
	}

	return findings
}

func optionTrue(options map[protocol.Option]bool, option protocol.Option) bool {
	value, ok := options[option]

	return ok && value
}

func pinUVAuthProtocolKey(input protocol.PinUvAuthProtocol) string {
	return fmt.Sprint(uint(input))
}

func stringKey(input string) string {
	return input
}

func algorithmKey(input credential.PublicKeyCredentialParameters) string {
	typ := input.Type
	if typ == "" {
		typ = credential.PublicKeyCredentialTypePublicKey
	}

	return fmt.Sprintf("%s:%d", typ, input.Algorithm)
}
