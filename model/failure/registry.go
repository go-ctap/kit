package failure

import (
	"strconv"
)

type paramValueRule string

const (
	paramValueField         paramValueRule = "field"
	paramValueUint          paramValueRule = "uint"
	paramValueHTTPStatus    paramValueRule = "http-status"
	paramValueSpecification paramValueRule = "specification"
	paramValueProfile       paramValueRule = "profile"
)

var paramValueEnums = map[paramValueRule]map[string]struct{}{
	paramValueField: values(
		"pin",
		"currentPIN",
		"newPIN",
	),
	paramValueSpecification: values(
		"ctap-2.0-ps-20190130",
		"ctap-2.1-ps-20210615",
		"ctap-2.3-ps-20260226",
	),
	paramValueProfile: values(
		"FIDO_2_0",
		"FIDO_2_1_PRE",
		"FIDO_2_1",
		"FIDO_2_3",
		"U2F_V2",
	),
}

type codeSpec struct {
	category Category
	params   map[string]paramValueRule
}

var codeRegistry = newCodeRegistry()

func newCodeRegistry() map[Code]codeSpec {
	registry := make(map[Code]codeSpec)
	register := func(category Category, codes ...Code) {
		for _, code := range codes {
			registry[code] = codeSpec{category: category}
		}
	}
	allow := func(code Code, rules map[string]paramValueRule) {
		spec := registry[code]
		spec.params = rules
		registry[code] = spec
	}

	register(CategoryInternal, CodeInternalError)
	register(CategoryUnsupported,
		CodeOperationUnsupported,
		CodeVerificationFlowUnsupported,
		CodeTransportModeUnsupported,
		CodeCredentialManagementUnsupported,
		CodePINUnsupported,
		CodeBioUnsupported,
		CodeAuthenticatorConfigUnsupported,
		CodeMinPINLengthUnsupported,
		CodeLargeBlobUnsupported,
		CodeLargeBlobDecodeModeUnsupported,
		CodeCTAPCommandInvalid,
		CodeAlgorithmUnsupported,
		CodeCTAPOptionUnsupported,
		CodeCTAPSubcommandInvalid,
		CodeGetInfoUnsupported,
	)
	register(CategoryPermissionDenied,
		CodeTransportPermissionDenied,
	)
	register(CategoryTransportFailure,
		CodeTransportProxyUnavailable,
		CodeTransportFailure,
		CodeMDSFetchFailed,
		CodeCTAPSequenceInvalid,
		CodeCTAPLockRequired,
		CodeCTAPChannelInvalid,
		CodeCTAPIntegrityFailure,
		CodeCTAPOtherError,
		CodeCTAPReservedStatus,
		CodeCTAPExtensionError,
		CodeCTAPVendorError,
	)
	register(CategoryTimeout,
		CodeOperationTimeout,
		CodeResetTouchTimeout,
		CodeAuthenticatorTimeout,
		CodeUserActionTimeout,
		CodeAuthenticatorActionTimeout,
		CodeAuthenticatorSelectionTimeout,
		CodeBioInteractionTimeout,
	)
	register(CategoryBusy,
		CodeAuthenticatorBusy,
		CodeAuthenticatorProcessing,
		CodeUserActionPending,
		CodeAuthenticatorOperationPending,
	)
	register(CategoryInvalidSession,
		CodeSessionInvalid,
		CodeSessionClosed,
	)
	register(CategoryCanceled,
		CodeOperationCanceled,
		CodeInteractionCanceled,
		CodeAuthenticatorOperationCanceled,
		CodeAuthenticatorSelectionCanceled,
	)
	register(CategoryInvalidOperation,
		CodeOperationRequired,
		CodeRequestJSONInvalid,
		CodeConfirmationRequired,
		CodeInteractionKindRequired,
		CodeInteractionHandlerRequired,
		CodeDeviceHandleInvalid,
		CodeDeviceSelectionRequired,
		CodeMDSAAGUIDInvalid,
		CodeConformanceTargetInvalid,
		CodeRelyingPartyIDRequired,
		CodeUserIDRequired,
		CodeClientDataJSONRequired,
		CodePublicKeyCredentialParametersRequired,
		CodePublicKeyCredentialAlgorithmRequired,
		CodeCredentialIDRequired,
		CodeCredentialChangesRequired,
		CodeUserIDHexInvalid,
		CodePINRequired,
		CodeBioTemplateIDRequired,
		CodeBioTemplateIDInvalid,
		CodeLargeBlobArrayInvalid,
		CodeLargeBlobWriteSequenceInvalid,
		CodeCTAPParameterInvalid,
		CodeCTAPLengthInvalid,
		CodeCTAPCBORTypeInvalid,
		CodeCTAPCBORInvalid,
		CodeCTAPParameterMissing,
		CodeCTAPLimitExceeded,
		CodeCTAPOptionInvalid,
		CodeCTAPRequestTooLarge,
	)
	register(CategoryInvalidState,
		CodeServiceClosed,
		CodeDeviceNotFound,
		CodeDeviceUnavailable,
		CodeMDSVerificationFailed,
		CodeCredentialNotFound,
		CodeCredentialExcluded,
		CodeCredentialStoreFull,
		CodeAttestedCredentialDataMissing,
		CodeCredentialCreationDenied,
		CodeAssertionDenied,
		CodeAssertionNotAllowed,
		CodeAssertionContinuationUnavailable,
		CodePINAlreadyConfigured,
		CodePINNotConfigured,
		CodePINInvalid,
		CodePINBlocked,
		CodePINUVAuthInvalid,
		CodePINUVAuthBlocked,
		CodePINPolicyViolation,
		CodePINUVAuthTokenRequired,
		CodePINUVPermissionUnauthorized,
		CodeUserPresenceRequired,
		CodeUserVerificationBlocked,
		CodeUserVerificationInvalid,
		CodeBioNoEnrollments,
		CodeBioEnrollmentNotFound,
		CodeBioDatabaseFull,
		CodeAuthenticatorConfigStorageFull,
		CodeAuthenticatorOperationDenied,
		CodeAuthenticatorOperationNotAllowed,
		CodeAlwaysUVStateUnknown,
		CodeAlwaysUVAlreadyTarget,
		CodeMinPINLengthDecreaseNotAllowed,
		CodeResetWindowExpired,
		CodeLargeBlobKeyMissing,
		CodeLargeBlobArrayTooLarge,
		CodeLargeBlobStorageFull,
		CodeLargeBlobIntegrityFailure,
		CodeLargeBlobMissing,
		CodeLargeBlobUTF8Invalid,
		CodeLargeBlobJSONInvalid,
		CodeLargeBlobCBORInvalid,
		CodeCredentialInvalid,
		CodeAuthenticatorNoOperations,
	)

	allow(CodePINRequired, map[string]paramValueRule{
		"field": paramValueField,
	})
	allow(CodeMDSFetchFailed, map[string]paramValueRule{
		"httpStatus": paramValueHTTPStatus,
	})
	allow(CodeConformanceTargetInvalid, map[string]paramValueRule{
		"profile":       paramValueProfile,
		"specification": paramValueSpecification,
	})
	allow(CodeMinPINLengthDecreaseNotAllowed, map[string]paramValueRule{
		"current":   paramValueUint,
		"requested": paramValueUint,
	})
	allow(CodeLargeBlobArrayTooLarge, map[string]paramValueRule{
		"limit":     paramValueUint,
		"requested": paramValueUint,
	})

	return registry
}

func validParamValue(rule paramValueRule, value string) bool {
	if allowed, isEnum := paramValueEnums[rule]; isEnum {
		_, valid := allowed[value]
		return valid
	}

	switch rule {
	case paramValueUint:
		return isCanonicalUint(value)
	case paramValueHTTPStatus:
		status, err := strconv.ParseUint(value, 10, 16)
		return err == nil && status >= 100 && status <= 599 && strconv.FormatUint(status, 10) == value
	default:
		return false
	}
}

func isCanonicalUint(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && strconv.FormatUint(parsed, 10) == value
}

func values(entries ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		result[entry] = struct{}{}
	}

	return result
}
