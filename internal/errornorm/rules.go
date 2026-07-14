package errornorm

import (
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/model/failure"
)

func codeForCTAP(status ctaptransport.StatusCode, ctx errorContext) failure.Code {
	if code, ok := commandCode(status, ctx); ok {
		return code
	}

	return defaultCode(status)
}

func commandCode(status ctaptransport.StatusCode, ctx errorContext) (failure.Code, bool) {
	switch ctx.command {
	case protocol.AuthenticatorMakeCredential:
		if status == ctaptransport.CTAP2_ERR_OPERATION_DENIED {
			return failure.CodeCredentialCreationDenied, true
		}
	case protocol.AuthenticatorGetAssertion:
		switch status {
		case ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL:
			return failure.CodeCredentialNotFound, true
		case ctaptransport.CTAP2_ERR_OPERATION_DENIED:
			return failure.CodeAssertionDenied, true
		case ctaptransport.CTAP2_ERR_NOT_ALLOWED:
			return failure.CodeAssertionNotAllowed, true
		}
	case protocol.AuthenticatorGetNextAssertion:
		if status == ctaptransport.CTAP2_ERR_NOT_ALLOWED {
			return failure.CodeAssertionContinuationUnavailable, true
		}
	case protocol.AuthenticatorGetInfo:
		if status == ctaptransport.CTAP1_ERR_INVALID_COMMAND {
			return failure.CodeGetInfoUnsupported, true
		}
	case protocol.AuthenticatorReset:
		switch status {
		case ctaptransport.CTAP2_ERR_NOT_ALLOWED:
			return failure.CodeResetWindowExpired, true
		case ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, ctaptransport.CTAP2_ERR_ACTION_TIMEOUT:
			return failure.CodeResetTouchTimeout, true
		}
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		return bioEnrollmentCode(status, ctx)
	case protocol.AuthenticatorCredentialManagement, protocol.PrototypeAuthenticatorCredentialManagement:
		if status == ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL {
			return failure.CodeCredentialNotFound, true
		}
	case protocol.AuthenticatorSelection:
		switch status {
		case ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL:
			return failure.CodeAuthenticatorSelectionCanceled, true
		case ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, ctaptransport.CTAP2_ERR_ACTION_TIMEOUT:
			return failure.CodeAuthenticatorSelectionTimeout, true
		}
	case protocol.AuthenticatorLargeBlobs:
		switch status {
		case ctaptransport.CTAP1_ERR_INVALID_SEQ:
			return failure.CodeLargeBlobWriteSequenceInvalid, true
		case ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE:
			return failure.CodeLargeBlobIntegrityFailure, true
		}
	case protocol.AuthenticatorConfig:
		if status == ctaptransport.CTAP2_ERR_KEY_STORE_FULL {
			return failure.CodeAuthenticatorConfigStorageFull, true
		}
	}

	return "", false
}

func bioEnrollmentCode(status ctaptransport.StatusCode, ctx errorContext) (failure.Code, bool) {
	switch status {
	case ctaptransport.CTAP2_ERR_INVALID_OPTION:
		switch protocol.BioEnrollmentSubCommand(ctx.subCommand) {
		case protocol.BioEnrollmentSubCommandEnumerateEnrollments:
			return failure.CodeBioNoEnrollments, true
		case protocol.BioEnrollmentSubCommandSetFriendlyName,
			protocol.BioEnrollmentSubCommandRemoveEnrollment:
			return failure.CodeBioEnrollmentNotFound, true
		}
	case ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, ctaptransport.CTAP2_ERR_ACTION_TIMEOUT:
		return failure.CodeBioInteractionTimeout, true
	}

	return "", false
}

func defaultCode(status ctaptransport.StatusCode) failure.Code {
	switch status {
	case ctaptransport.CTAP1_ERR_INVALID_COMMAND:
		return failure.CodeCTAPCommandInvalid
	case ctaptransport.CTAP1_ERR_INVALID_PARAMETER:
		return failure.CodeCTAPParameterInvalid
	case ctaptransport.CTAP1_ERR_INVALID_LENGTH:
		return failure.CodeCTAPLengthInvalid
	case ctaptransport.CTAP1_ERR_INVALID_SEQ:
		return failure.CodeCTAPSequenceInvalid
	case ctaptransport.CTAP1_ERR_TIMEOUT:
		return failure.CodeAuthenticatorTimeout
	case ctaptransport.CTAP1_ERR_CHANNEL_BUSY:
		return failure.CodeAuthenticatorBusy
	case ctaptransport.CTAP1_ERR_LOCK_REQUIRED:
		return failure.CodeCTAPLockRequired
	case ctaptransport.CTAP1_ERR_INVALID_CHANNEL:
		return failure.CodeCTAPChannelInvalid
	case ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE:
		return failure.CodeCTAPCBORTypeInvalid
	case ctaptransport.CTAP2_ERR_INVALID_CBOR:
		return failure.CodeCTAPCBORInvalid
	case ctaptransport.CTAP2_ERR_MISSING_PARAMETER:
		return failure.CodeCTAPParameterMissing
	case ctaptransport.CTAP2_ERR_LIMIT_EXCEEDED:
		return failure.CodeCTAPLimitExceeded
	case ctaptransport.CTAP2_ERR_FP_DATABASE_FULL:
		return failure.CodeBioDatabaseFull
	case ctaptransport.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL:
		return failure.CodeLargeBlobStorageFull
	case ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED:
		return failure.CodeCredentialExcluded
	case ctaptransport.CTAP2_ERR_PROCESSING:
		return failure.CodeAuthenticatorProcessing
	case ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL:
		return failure.CodeCredentialInvalid
	case ctaptransport.CTAP2_ERR_USER_ACTION_PENDING:
		return failure.CodeUserActionPending
	case ctaptransport.CTAP2_ERR_OPERATION_PENDING:
		return failure.CodeAuthenticatorOperationPending
	case ctaptransport.CTAP2_ERR_NO_OPERATIONS:
		return failure.CodeAuthenticatorNoOperations
	case ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM:
		return failure.CodeAlgorithmUnsupported
	case ctaptransport.CTAP2_ERR_OPERATION_DENIED:
		return failure.CodeAuthenticatorOperationDenied
	case ctaptransport.CTAP2_ERR_KEY_STORE_FULL:
		return failure.CodeCredentialStoreFull
	case ctaptransport.CTAP2_ERR_UNSUPPORTED_OPTION:
		return failure.CodeCTAPOptionUnsupported
	case ctaptransport.CTAP2_ERR_INVALID_OPTION:
		return failure.CodeCTAPOptionInvalid
	case ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL:
		return failure.CodeAuthenticatorOperationCanceled
	case ctaptransport.CTAP2_ERR_NO_CREDENTIALS:
		return failure.CodeCredentialNotFound
	case ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT:
		return failure.CodeUserActionTimeout
	case ctaptransport.CTAP2_ERR_NOT_ALLOWED:
		return failure.CodeAuthenticatorOperationNotAllowed
	case ctaptransport.CTAP2_ERR_PIN_INVALID:
		return failure.CodePINInvalid
	case ctaptransport.CTAP2_ERR_PIN_BLOCKED:
		return failure.CodePINBlocked
	case ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID:
		return failure.CodePINUVAuthInvalid
	case ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED:
		return failure.CodePINUVAuthBlocked
	case ctaptransport.CTAP2_ERR_PIN_NOT_SET:
		return failure.CodePINNotConfigured
	case ctaptransport.CTAP2_ERR_PUAT_REQUIRED:
		return failure.CodePINUVAuthTokenRequired
	case ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION:
		return failure.CodePINPolicyViolation
	case ctaptransport.RESERVED_FOR_FUTURE_USE:
		return failure.CodeCTAPReservedStatus
	case ctaptransport.CTAP2_ERR_REQUEST_TOO_LARGE:
		return failure.CodeCTAPRequestTooLarge
	case ctaptransport.CTAP2_ERR_ACTION_TIMEOUT:
		return failure.CodeAuthenticatorActionTimeout
	case ctaptransport.CTAP2_ERR_UP_REQUIRED:
		return failure.CodeUserPresenceRequired
	case ctaptransport.CTAP2_ERR_UV_BLOCKED:
		return failure.CodeUserVerificationBlocked
	case ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE:
		return failure.CodeCTAPIntegrityFailure
	case ctaptransport.CTAP2_ERR_INVALID_SUBCOMMAND:
		return failure.CodeCTAPSubcommandInvalid
	case ctaptransport.CTAP2_ERR_UV_INVALID:
		return failure.CodeUserVerificationInvalid
	case ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION:
		return failure.CodePINUVPermissionUnauthorized
	case ctaptransport.CTAP1_ERR_OTHER:
		return failure.CodeCTAPOtherError
	default:
		switch {
		case status >= ctaptransport.CTAP2_ERR_VENDOR_FIRST:
			return failure.CodeCTAPVendorError
		case status >= ctaptransport.CTAP2_ERR_EXTENSION_FIRST:
			return failure.CodeCTAPExtensionError
		case status > ctaptransport.CTAP2_OK:
			return failure.CodeCTAPReservedStatus
		default:
			return failure.CodeInternalError
		}
	}
}
