package conformance

type FindingID string

const (
	FindingVersionsRequired                    FindingID = "versions_required"
	FindingFIDO22Forbidden                     FindingID = "fido22_forbidden"
	FindingPinUVAuthProtocolsListEmpty         FindingID = "pin_uv_auth_protocols_list_empty"
	FindingPinUVAuthProtocolsListDuplicate     FindingID = "pin_uv_auth_protocols_list_duplicate"
	FindingTransportsListEmpty                 FindingID = "transports_list_empty"
	FindingTransportsListDuplicate             FindingID = "transports_list_duplicate"
	FindingAlgorithmsListEmpty                 FindingID = "algorithms_list_empty"
	FindingAlgorithmsListDuplicate             FindingID = "algorithms_list_duplicate"
	FindingTransportsForResetListEmpty         FindingID = "transports_for_reset_list_empty"
	FindingTransportsForResetListDuplicate     FindingID = "transports_for_reset_list_duplicate"
	FindingAttestationFormatsListEmpty         FindingID = "attestation_formats_list_empty"
	FindingAttestationFormatsListDuplicate     FindingID = "attestation_formats_list_duplicate"
	FindingAttestationFormatsNone              FindingID = "attestation_formats_none"
	FindingMaxCredentialCountInListPositive    FindingID = "max_credential_count_in_list_positive"
	FindingMaxCredentialIDLengthPositive       FindingID = "max_credential_id_length_positive"
	FindingMaxMsgSizeMinimum                   FindingID = "max_msg_size_minimum"
	FindingPreferredPlatformUVAttemptsMinimum  FindingID = "preferred_platform_uv_attempts_minimum"
	FindingCTAP23HMACSecret                    FindingID = "ctap23_hmac_secret"
	FindingCTAP23RKUVState                     FindingID = "ctap23_rk_uv_state"
	FindingCTAP23PinUVAuthToken                FindingID = "ctap23_pin_uv_auth_token"
	FindingCTAP23PinProtocolTwo                FindingID = "ctap23_pin_protocol_two"
	FindingCredBlobRequiresCredProtect         FindingID = "credblob_requires_credprotect"
	FindingCredBlobRequiresLimit               FindingID = "credblob_requires_limit"
	FindingCredBlobLimitInvalid                FindingID = "credblob_limit_invalid"
	FindingCredBlobLimitWithoutExtension       FindingID = "credblob_limit_without_extension"
	FindingLargeBlobModeConflict               FindingID = "largeblob_mode_conflict"
	FindingLargeBlobExtensionsConflict         FindingID = "largeblob_extensions_conflict"
	FindingLargeBlobKeyIncomplete              FindingID = "largeblob_key_incomplete"
	FindingLargeBlobsRequiresLimit             FindingID = "largeblobs_requires_limit"
	FindingLargeBlobsLimitInvalid              FindingID = "largeblobs_limit_invalid"
	FindingLargeBlobsLimitWithoutCommand       FindingID = "largeblobs_limit_without_command"
	FindingMinPINExtensionWithoutOption        FindingID = "min_pin_extension_without_option"
	FindingSetMinPINWithoutExtension           FindingID = "set_min_pin_without_extension"
	FindingSetMinPINWithoutUV                  FindingID = "set_min_pin_without_uv"
	FindingSetMinPINCommandMissing             FindingID = "set_min_pin_command_missing"
	FindingMaxRPIDsWithoutSetMinPIN            FindingID = "max_rpids_without_set_min_pin"
	FindingMaxRPIDsMissingWithSetMinPIN        FindingID = "max_rpids_missing_with_set_min_pin"
	FindingMinPINLengthInvalid                 FindingID = "min_pin_length_invalid"
	FindingMinPINWithoutClientPIN              FindingID = "min_pin_without_client_pin"
	FindingMinPINMissing                       FindingID = "min_pin_missing"
	FindingMaxPINLengthInvalid                 FindingID = "max_pin_length_invalid"
	FindingMaxPINWithoutClientPIN              FindingID = "max_pin_without_client_pin"
	FindingPinComplexityExtensionWithoutSetPIN FindingID = "pin_complexity_extension_without_set_min_pin"
	FindingPinComplexityWithoutClientPIN       FindingID = "pin_complexity_without_client_pin"
	FindingNoMCGAWithoutClientPIN              FindingID = "no_mc_ga_without_client_pin"
	FindingUVBioEnrollWithoutBioEnroll         FindingID = "uv_bio_enroll_without_bio_enroll"
	FindingUVAcfgWithoutAuthnrCfg              FindingID = "uv_acfg_without_authnr_cfg"
	FindingConfigCommandsWithoutAuthnrCfg      FindingID = "config_commands_without_authnr_cfg"
	FindingAlwaysUVConflict                    FindingID = "always_uv_conflict"
	FindingAlwaysUVCommandMissing              FindingID = "always_uv_command_missing"
	FindingEnterpriseAttestationCommandMissing FindingID = "enterprise_attestation_command_missing"
	FindingVendorPrototypeCommandMissing       FindingID = "vendor_prototype_command_missing"
	FindingLongTouchCommandMissing             FindingID = "long_touch_command_missing"
)

type CommonValueID string

const (
	CommonValueEmptyList                        CommonValueID = "empty_list"
	CommonValueExtensionReportedCommandMissing  CommonValueID = "extension_reported_command_missing"
	CommonValueMutuallyExclusiveSupportReported CommonValueID = "mutually_exclusive_support_reported"
	CommonValueNotListed                        CommonValueID = "not_listed"
	CommonValueNotReported                      CommonValueID = "not_reported"
)

type FindingValueKind string

const (
	FindingValueCommon  FindingValueKind = "common"
	FindingValueLiteral FindingValueKind = "literal"
	FindingValueInput   FindingValueKind = "input"
	FindingValueList    FindingValueKind = "list"
)

type FindingValue struct {
	Kind  FindingValueKind `json:"kind"`
	ID    CommonValueID    `json:"id,omitempty"`
	Value string           `json:"value,omitempty"`
	Input any              `json:"input,omitempty"`
	Items []any            `json:"items,omitempty"`
}

type Finding struct {
	ID     FindingID      `json:"id"`
	Source string         `json:"source"`
	Value  FindingValue   `json:"value"`
	Args   map[string]any `json:"args,omitempty"`
}

func CommonValue(id CommonValueID) FindingValue {
	return FindingValue{Kind: FindingValueCommon, ID: id}
}

func LiteralValue(value string) FindingValue {
	return FindingValue{Kind: FindingValueLiteral, Value: value}
}

func InputValue(input any) FindingValue {
	return FindingValue{Kind: FindingValueInput, Input: input}
}

func ListValue(items []any) FindingValue {
	return FindingValue{Kind: FindingValueList, Items: items}
}
