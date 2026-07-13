package ctaperrors

import (
	"errors"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func TestNormalizeCommandAwareMatrix(t *testing.T) {
	tests := []struct {
		name      string
		ctx       Context
		status    ctaptransport.StatusCode
		category  model.ErrorCategory
		sentinel  error
		ctapError *ctaptransport.CTAPError
	}{
		{
			name:     "make credential excluded",
			ctx:      WithCommand("", protocol.AuthenticatorMakeCredential, ""),
			status:   ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED,
			category: model.ErrorInvalidState,
			sentinel: appcredentials.ErrCredentialExcluded,
		},
		{
			name:     "make credential store full",
			ctx:      WithCommand("", protocol.AuthenticatorMakeCredential, ""),
			status:   ctaptransport.CTAP2_ERR_KEY_STORE_FULL,
			category: model.ErrorInvalidState,
			sentinel: appcredentials.ErrCredentialStoreFull,
		},
		{
			name:     "get assertion no credentials",
			ctx:      WithCommand("", protocol.AuthenticatorGetAssertion, ""),
			status:   ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
			category: model.ErrorInvalidState,
			sentinel: appcredentials.ErrCredentialNotFound,
		},
		{
			name:     "get assertion invalid credential",
			ctx:      WithCommand("", protocol.AuthenticatorGetAssertion, ""),
			status:   ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL,
			category: model.ErrorInvalidState,
			sentinel: appcredentials.ErrCredentialNotFound,
		},
		{
			name:     "get next assertion no continuation",
			ctx:      WithCommand("", protocol.AuthenticatorGetNextAssertion, ""),
			status:   ctaptransport.CTAP2_ERR_NOT_ALLOWED,
			category: model.ErrorInvalidState,
		},
		{
			name:     "get info unsupported",
			ctx:      WithCommand("", protocol.AuthenticatorGetInfo, ""),
			status:   ctaptransport.CTAP1_ERR_INVALID_COMMAND,
			category: model.ErrorUnsupported,
		},
		{
			name:     "client pin invalid",
			ctx:      WithClientPINSubCommand("", protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions),
			status:   ctaptransport.CTAP2_ERR_PIN_INVALID,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrPINInvalid,
		},
		{
			name:     "client pin blocked",
			ctx:      WithClientPINSubCommand("", protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions),
			status:   ctaptransport.CTAP2_ERR_PIN_BLOCKED,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrPINBlocked,
		},
		{
			name:     "set pin auth invalid also means already configured",
			ctx:      WithClientPINSubCommand("", protocol.ClientPINSubCommandSetPIN),
			status:   ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrPINAlreadyConfigured,
		},
		{
			name:     "client pin policy violation",
			ctx:      WithClientPINSubCommand("", protocol.ClientPINSubCommandChangePIN),
			status:   ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrPINPolicyViolation,
		},
		{
			name:     "uv invalid",
			ctx:      WithClientPINSubCommand("", protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions),
			status:   ctaptransport.CTAP2_ERR_UV_INVALID,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrUserVerificationInvalid,
		},
		{
			name:     "reset window expired",
			ctx:      WithCommand("", protocol.AuthenticatorReset, DomainConfig),
			status:   ctaptransport.CTAP2_ERR_NOT_ALLOWED,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrResetWindowExpired,
		},
		{
			name:     "reset timeout",
			ctx:      WithCommand("", protocol.AuthenticatorReset, DomainConfig),
			status:   ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT,
			category: model.ErrorTimeout,
		},
		{
			name:     "bio database full",
			ctx:      WithBioEnrollmentSubCommand("", protocol.AuthenticatorBioEnrollment, protocol.BioEnrollmentSubCommandEnrollBegin),
			status:   ctaptransport.CTAP2_ERR_FP_DATABASE_FULL,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrBioDatabaseFull,
		},
		{
			name:     "prototype bio template missing",
			ctx:      WithBioEnrollmentSubCommand("", protocol.PrototypeAuthenticatorBioEnrollment, protocol.BioEnrollmentSubCommandRemoveEnrollment),
			status:   ctaptransport.CTAP2_ERR_INVALID_OPTION,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrBioEnrollmentNotFound,
		},
		{
			name:     "credential management no credentials",
			ctx:      WithCredentialManagementSubCommand("", protocol.AuthenticatorCredentialManagement, protocol.CredentialManagementSubCommandDeleteCredential),
			status:   ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
			category: model.ErrorInvalidState,
			sentinel: appcredentials.ErrCredentialNotFound,
		},
		{
			name:     "prototype credential management token invalid",
			ctx:      WithCredentialManagementSubCommand("", protocol.PrototypeAuthenticatorCredentialManagement, protocol.CredentialManagementSubCommandEnumerateRPsBegin),
			status:   ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrPINAuthInvalid,
		},
		{
			name:     "selection canceled",
			ctx:      WithCommand("", protocol.AuthenticatorSelection, ""),
			status:   ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL,
			category: model.ErrorCanceled,
		},
		{
			name:     "large blobs storage full",
			ctx:      WithLargeBlobsSubCommand("", LargeBlobsSubCommandSet),
			status:   ctaptransport.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL,
			category: model.ErrorInvalidState,
			sentinel: applargeblobs.ErrLargeBlobStorageFull,
		},
		{
			name:     "large blobs integrity failure",
			ctx:      WithLargeBlobsSubCommand("", LargeBlobsSubCommandSet),
			status:   ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE,
			category: model.ErrorInvalidState,
			sentinel: applargeblobs.ErrLargeBlobIntegrity,
		},
		{
			name:     "config operation denied",
			ctx:      WithConfigSubCommand("", protocol.ConfigSubCommandToggleAlwaysUv),
			status:   ctaptransport.CTAP2_ERR_OPERATION_DENIED,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrOperationDenied,
		},
		{
			name:     "config min pin key store full",
			ctx:      WithConfigSubCommand("", protocol.ConfigSubCommandSetMinPINLength),
			status:   ctaptransport.CTAP2_ERR_KEY_STORE_FULL,
			category: model.ErrorInvalidState,
			sentinel: appconfig.ErrAuthenticatorConfigStorageFull,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctapErr := &ctaptransport.CTAPError{
				Command:    tt.ctx.Command,
				StatusCode: tt.status,
			}
			err := Normalize(Annotate(ctapErr, tt.ctx))

			if !model.IsErrorCategory(err, tt.category) {
				t.Fatalf("Normalize category = %v, want %s", err, tt.category)
			}
			if tt.sentinel != nil && !errors.Is(err, tt.sentinel) {
				t.Fatalf("Normalize error = %v, want sentinel %v", err, tt.sentinel)
			}
			if !errors.As(err, &tt.ctapError) {
				t.Fatalf("Normalize error = %v, want original CTAPError in chain", err)
			}
		})
	}
}

func TestNormalizeGenericStatusCoverage(t *testing.T) {
	tests := []struct {
		name     string
		status   ctaptransport.StatusCode
		category model.ErrorCategory
	}{
		{name: "ctap ok as failure fallback", status: ctaptransport.CTAP2_OK, category: model.ErrorTransportFailure},
		{name: "ctap1 invalid command", status: ctaptransport.CTAP1_ERR_INVALID_COMMAND, category: model.ErrorUnsupported},
		{name: "ctap1 invalid parameter", status: ctaptransport.CTAP1_ERR_INVALID_PARAMETER, category: model.ErrorInvalidOperation},
		{name: "ctap1 invalid length", status: ctaptransport.CTAP1_ERR_INVALID_LENGTH, category: model.ErrorInvalidOperation},
		{name: "ctap1 invalid seq", status: ctaptransport.CTAP1_ERR_INVALID_SEQ, category: model.ErrorTransportFailure},
		{name: "ctap1 timeout", status: ctaptransport.CTAP1_ERR_TIMEOUT, category: model.ErrorTimeout},
		{name: "ctap1 channel busy", status: ctaptransport.CTAP1_ERR_CHANNEL_BUSY, category: model.ErrorBusy},
		{name: "ctap1 lock required", status: ctaptransport.CTAP1_ERR_LOCK_REQUIRED, category: model.ErrorTransportFailure},
		{name: "ctap1 invalid channel", status: ctaptransport.CTAP1_ERR_INVALID_CHANNEL, category: model.ErrorTransportFailure},
		{name: "cbor unexpected type", status: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE, category: model.ErrorInvalidOperation},
		{name: "invalid cbor", status: ctaptransport.CTAP2_ERR_INVALID_CBOR, category: model.ErrorInvalidOperation},
		{name: "missing parameter", status: ctaptransport.CTAP2_ERR_MISSING_PARAMETER, category: model.ErrorInvalidOperation},
		{name: "limit exceeded", status: ctaptransport.CTAP2_ERR_LIMIT_EXCEEDED, category: model.ErrorInvalidOperation},
		{name: "fp database full", status: ctaptransport.CTAP2_ERR_FP_DATABASE_FULL, category: model.ErrorInvalidState},
		{name: "large blob storage full", status: ctaptransport.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL, category: model.ErrorInvalidState},
		{name: "credential excluded", status: ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED, category: model.ErrorInvalidState},
		{name: "processing", status: ctaptransport.CTAP2_ERR_PROCESSING, category: model.ErrorBusy},
		{name: "invalid credential", status: ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, category: model.ErrorInvalidState},
		{name: "user action pending", status: ctaptransport.CTAP2_ERR_USER_ACTION_PENDING, category: model.ErrorBusy},
		{name: "operation pending", status: ctaptransport.CTAP2_ERR_OPERATION_PENDING, category: model.ErrorBusy},
		{name: "no operations", status: ctaptransport.CTAP2_ERR_NO_OPERATIONS, category: model.ErrorInvalidState},
		{name: "unsupported algorithm", status: ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM, category: model.ErrorUnsupported},
		{name: "operation denied", status: ctaptransport.CTAP2_ERR_OPERATION_DENIED, category: model.ErrorInvalidState},
		{name: "key store full", status: ctaptransport.CTAP2_ERR_KEY_STORE_FULL, category: model.ErrorInvalidState},
		{name: "unsupported option", status: ctaptransport.CTAP2_ERR_UNSUPPORTED_OPTION, category: model.ErrorUnsupported},
		{name: "invalid option", status: ctaptransport.CTAP2_ERR_INVALID_OPTION, category: model.ErrorInvalidOperation},
		{name: "keepalive cancel", status: ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL, category: model.ErrorCanceled},
		{name: "no credentials", status: ctaptransport.CTAP2_ERR_NO_CREDENTIALS, category: model.ErrorInvalidState},
		{name: "user action timeout", status: ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, category: model.ErrorTimeout},
		{name: "not allowed", status: ctaptransport.CTAP2_ERR_NOT_ALLOWED, category: model.ErrorInvalidState},
		{name: "pin invalid", status: ctaptransport.CTAP2_ERR_PIN_INVALID, category: model.ErrorInvalidState},
		{name: "pin blocked", status: ctaptransport.CTAP2_ERR_PIN_BLOCKED, category: model.ErrorInvalidState},
		{name: "pin auth invalid", status: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID, category: model.ErrorInvalidState},
		{name: "pin auth blocked", status: ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED, category: model.ErrorInvalidState},
		{name: "pin not set", status: ctaptransport.CTAP2_ERR_PIN_NOT_SET, category: model.ErrorInvalidState},
		{name: "pin uv auth token required", status: ctaptransport.CTAP2_ERR_PUAT_REQUIRED, category: model.ErrorInvalidState},
		{name: "pin policy violation", status: ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION, category: model.ErrorInvalidState},
		{name: "request too large", status: ctaptransport.CTAP2_ERR_REQUEST_TOO_LARGE, category: model.ErrorInvalidOperation},
		{name: "action timeout", status: ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, category: model.ErrorTimeout},
		{name: "user presence required", status: ctaptransport.CTAP2_ERR_UP_REQUIRED, category: model.ErrorInvalidState},
		{name: "uv blocked", status: ctaptransport.CTAP2_ERR_UV_BLOCKED, category: model.ErrorInvalidState},
		{name: "integrity failure", status: ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE, category: model.ErrorTransportFailure},
		{name: "invalid subcommand", status: ctaptransport.CTAP2_ERR_INVALID_SUBCOMMAND, category: model.ErrorUnsupported},
		{name: "uv invalid", status: ctaptransport.CTAP2_ERR_UV_INVALID, category: model.ErrorInvalidState},
		{name: "unauthorized permission", status: ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION, category: model.ErrorInvalidState},
		{name: "ctap1 other", status: ctaptransport.CTAP1_ERR_OTHER, category: model.ErrorTransportFailure},
		{name: "spec last", status: ctaptransport.CTAP2_ERR_SPEC_LAST, category: model.ErrorTransportFailure},
		{name: "extension first", status: ctaptransport.CTAP2_ERR_EXTENSION_FIRST, category: model.ErrorTransportFailure},
		{name: "extension last", status: ctaptransport.CTAP2_ERR_EXTENSION_LAST, category: model.ErrorTransportFailure},
		{name: "vendor first", status: ctaptransport.CTAP2_ERR_VENDOR_FIRST, category: model.ErrorTransportFailure},
		{name: "vendor last", status: ctaptransport.CTAP2_ERR_VENDOR_LAST, category: model.ErrorTransportFailure},
		{name: "unknown reserved byte", status: ctaptransport.StatusCode(0x41), category: model.ErrorTransportFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Normalize(&ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorMakeCredential,
				StatusCode: tt.status,
			})

			if !model.IsErrorCategory(err, tt.category) {
				t.Fatalf("Normalize category = %v, want %s", err, tt.category)
			}
		})
	}
}
