package errornorm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	ctapdevice "github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	ctaptoken2 "github.com/go-ctap/ctap/transport/token2"
	"github.com/go-ctap/kit/model/failure"
)

func TestDefaultCode(t *testing.T) {
	tests := []struct {
		status ctaptransport.StatusCode
		code   failure.Code
	}{
		{ctaptransport.CTAP1_ERR_INVALID_COMMAND, failure.CodeCTAPCommandInvalid},
		{ctaptransport.CTAP1_ERR_INVALID_PARAMETER, failure.CodeCTAPParameterInvalid},
		{ctaptransport.CTAP1_ERR_INVALID_LENGTH, failure.CodeCTAPLengthInvalid},
		{ctaptransport.CTAP1_ERR_INVALID_SEQ, failure.CodeCTAPSequenceInvalid},
		{ctaptransport.CTAP1_ERR_TIMEOUT, failure.CodeAuthenticatorTimeout},
		{ctaptransport.CTAP1_ERR_CHANNEL_BUSY, failure.CodeAuthenticatorBusy},
		{ctaptransport.CTAP1_ERR_LOCK_REQUIRED, failure.CodeCTAPLockRequired},
		{ctaptransport.CTAP1_ERR_INVALID_CHANNEL, failure.CodeCTAPChannelInvalid},
		{ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE, failure.CodeCTAPCBORTypeInvalid},
		{ctaptransport.CTAP2_ERR_INVALID_CBOR, failure.CodeCTAPCBORInvalid},
		{ctaptransport.CTAP2_ERR_MISSING_PARAMETER, failure.CodeCTAPParameterMissing},
		{ctaptransport.CTAP2_ERR_LIMIT_EXCEEDED, failure.CodeCTAPLimitExceeded},
		{ctaptransport.CTAP2_ERR_FP_DATABASE_FULL, failure.CodeBioDatabaseFull},
		{ctaptransport.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL, failure.CodeLargeBlobStorageFull},
		{ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED, failure.CodeCredentialExcluded},
		{ctaptransport.CTAP2_ERR_PROCESSING, failure.CodeAuthenticatorProcessing},
		{ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, failure.CodeCredentialInvalid},
		{ctaptransport.CTAP2_ERR_USER_ACTION_PENDING, failure.CodeUserActionPending},
		{ctaptransport.CTAP2_ERR_OPERATION_PENDING, failure.CodeAuthenticatorOperationPending},
		{ctaptransport.CTAP2_ERR_NO_OPERATIONS, failure.CodeAuthenticatorNoOperations},
		{ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM, failure.CodeAlgorithmUnsupported},
		{ctaptransport.CTAP2_ERR_OPERATION_DENIED, failure.CodeAuthenticatorOperationDenied},
		{ctaptransport.CTAP2_ERR_KEY_STORE_FULL, failure.CodeCredentialStoreFull},
		{ctaptransport.CTAP2_ERR_UNSUPPORTED_OPTION, failure.CodeCTAPOptionUnsupported},
		{ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeCTAPOptionInvalid},
		{ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL, failure.CodeAuthenticatorOperationCanceled},
		{ctaptransport.CTAP2_ERR_NO_CREDENTIALS, failure.CodeCredentialNotFound},
		{ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeUserActionTimeout},
		{ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeAuthenticatorOperationNotAllowed},
		{ctaptransport.CTAP2_ERR_PIN_INVALID, failure.CodePINInvalid},
		{ctaptransport.CTAP2_ERR_PIN_BLOCKED, failure.CodePINBlocked},
		{ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID, failure.CodePINUVAuthInvalid},
		{ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED, failure.CodePINUVAuthBlocked},
		{ctaptransport.CTAP2_ERR_PIN_NOT_SET, failure.CodePINNotConfigured},
		{ctaptransport.CTAP2_ERR_PUAT_REQUIRED, failure.CodePINUVAuthTokenRequired},
		{ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION, failure.CodePINPolicyViolation},
		{ctaptransport.RESERVED_FOR_FUTURE_USE, failure.CodeCTAPReservedStatus},
		{ctaptransport.CTAP2_ERR_REQUEST_TOO_LARGE, failure.CodeCTAPRequestTooLarge},
		{ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeAuthenticatorActionTimeout},
		{ctaptransport.CTAP2_ERR_UP_REQUIRED, failure.CodeUserPresenceRequired},
		{ctaptransport.CTAP2_ERR_UV_BLOCKED, failure.CodeUserVerificationBlocked},
		{ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE, failure.CodeCTAPIntegrityFailure},
		{ctaptransport.CTAP2_ERR_INVALID_SUBCOMMAND, failure.CodeCTAPSubcommandInvalid},
		{ctaptransport.CTAP2_ERR_UV_INVALID, failure.CodeUserVerificationInvalid},
		{ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION, failure.CodePINUVPermissionUnauthorized},
		{ctaptransport.CTAP1_ERR_OTHER, failure.CodeCTAPOtherError},
		{0x41, failure.CodeCTAPReservedStatus},
		{0xe1, failure.CodeCTAPExtensionError},
		{0xf1, failure.CodeCTAPVendorError},
		{ctaptransport.CTAP2_OK, failure.CodeInternalError},
	}

	for _, tt := range tests {
		if got := defaultCode(tt.status); got != tt.code {
			t.Errorf("defaultCode(0x%02x) = %s, want %s", uint8(tt.status), got, tt.code)
		}
	}
}

func TestNormalizeCTAPProvenance(t *testing.T) {
	raw := &ctaptransport.CTAPError{
		Command:    protocol.Command(0x7e),
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}
	err := Normalize(raw, "inspect")
	assertFailure(t, err, failure.CodePINInvalid, "inspect", failure.PhaseAuthenticatorCommand)

	detail := failure.Snapshot(err).CTAP
	if detail == nil {
		t.Fatal("CTAP detail = nil")
	}
	if detail.Command != "" || detail.CommandCode != 0x7e {
		t.Fatalf("command = %#v, want unknown command byte 0x7e", detail)
	}
	if detail.Status != "CTAP2_ERR_PIN_INVALID" || detail.StatusCode != uint8(ctaptransport.CTAP2_ERR_PIN_INVALID) {
		t.Fatalf("status = %#v, want CTAP2_ERR_PIN_INVALID", detail)
	}

	var gotRaw *ctaptransport.CTAPError
	if !errors.As(err, &gotRaw) || gotRaw != raw {
		t.Fatalf("errors.As CTAPError = %p, want %p", gotRaw, raw)
	}
}

func TestNormalizeCTAPHIDErrorResponse(t *testing.T) {
	raw := &ctaphid.ErrorResponse{ErrorCode: ctaphid.ERR_OTHER}
	err := Normalize(Annotate(raw, commandContext(
		protocol.AuthenticatorGetAssertion,
	)), "webauthn.getAssertion")
	assertFailure(
		t,
		err,
		failure.CodeTransportFailure,
		"webauthn.getAssertion",
		failure.PhaseAuthenticatorCommand,
	)
	if failure.Snapshot(err).CTAP != nil {
		t.Fatalf("CTAPHID error acquired CBOR CTAP detail: %#v", failure.Snapshot(err).CTAP)
	}

	var gotRaw *ctaphid.ErrorResponse
	if !errors.As(err, &gotRaw) || gotRaw != raw {
		t.Fatalf("errors.As ErrorResponse = %p, want %p", gotRaw, raw)
	}
}

func TestNormalizeTransportIOError(t *testing.T) {
	rawCause := io.ErrClosedPipe
	raw := &ctaptransport.IOError{Operation: ctaptransport.IOWrite, Err: rawCause}

	err := Normalize(Annotate(raw, WithCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorGetAssertion,
	)), "webauthn.getAssertion")
	assertFailure(
		t,
		err,
		failure.CodeTransportFailure,
		"webauthn.getAssertion",
		failure.PhaseAuthenticatorCommand,
	)
	if failure.Snapshot(err).CTAP != nil {
		t.Fatalf("device I/O error acquired CTAP detail: %#v", failure.Snapshot(err).CTAP)
	}
	var gotIOErr *ctaptransport.IOError
	if !errors.As(err, &gotIOErr) || gotIOErr != raw {
		t.Fatalf("errors.As IOError = %p, want %p", gotIOErr, raw)
	}
	if !errors.Is(err, rawCause) {
		t.Fatal("device I/O cause not preserved")
	}
}

func TestNormalizeToken2TransportErrors(t *testing.T) {
	t.Run("APDU status", func(t *testing.T) {
		raw := &ctaptoken2.APDUError{SW1: 0x6a, SW2: 0x82}
		err := Normalize(Annotate(raw, WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorGetAssertion,
		)), "webauthn.getAssertion")
		assertFailure(
			t,
			err,
			failure.CodeTransportFailure,
			"webauthn.getAssertion",
			failure.PhaseAuthenticatorCommand,
		)
		if failure.Snapshot(err).CTAP != nil {
			t.Fatalf("APDU error acquired CTAP detail: %#v", failure.Snapshot(err).CTAP)
		}

		var got *ctaptoken2.APDUError
		if !errors.As(err, &got) || got != raw {
			t.Fatalf("errors.As APDUError = %p, want %p", got, raw)
		}
	})

	for _, sentinel := range []error{
		ctaptoken2.ErrInvalidResponse,
		ctaptoken2.ErrCommandTooLarge,
	} {
		err := Normalize(sentinel, "inspect")
		assertFailure(t, err, failure.CodeTransportFailure, "inspect", "")
		if !errors.Is(err, sentinel) {
			t.Fatalf("transport sentinel %v not preserved", sentinel)
		}
	}
}

func TestNormalizeCommandOverrides(t *testing.T) {
	tests := []struct {
		ctx    errorContext
		status ctaptransport.StatusCode
		code   failure.Code
	}{
		{commandContext(protocol.AuthenticatorMakeCredential), ctaptransport.CTAP2_ERR_OPERATION_DENIED, failure.CodeCredentialCreationDenied},
		{commandContext(protocol.AuthenticatorGetAssertion), ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, failure.CodeCredentialNotFound},
		{commandContext(protocol.AuthenticatorGetAssertion), ctaptransport.CTAP2_ERR_OPERATION_DENIED, failure.CodeAssertionDenied},
		{commandContext(protocol.AuthenticatorGetAssertion), ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeAssertionNotAllowed},
		{commandContext(protocol.AuthenticatorGetNextAssertion), ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeAssertionContinuationUnavailable},
		{commandContext(protocol.AuthenticatorGetInfo), ctaptransport.CTAP1_ERR_INVALID_COMMAND, failure.CodeGetInfoUnsupported},
		{commandContext(protocol.AuthenticatorReset), ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeResetWindowExpired},
		{commandContext(protocol.AuthenticatorReset), ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeResetTouchTimeout},
		{commandContext(protocol.AuthenticatorReset), ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeResetTouchTimeout},
		{bioContext(protocol.BioEnrollmentSubCommandEnumerateEnrollments), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeBioNoEnrollments},
		{bioContext(protocol.BioEnrollmentSubCommandSetFriendlyName), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeBioEnrollmentNotFound},
		{bioContext(protocol.BioEnrollmentSubCommandRemoveEnrollment), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeBioEnrollmentNotFound},
		{bioContext(protocol.BioEnrollmentSubCommandEnrollBegin), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeCTAPOptionInvalid},
		{bioContext(protocol.BioEnrollmentSubCommandEnrollBegin), ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeBioInteractionTimeout},
		{bioContext(protocol.BioEnrollmentSubCommandEnrollBegin), ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeBioInteractionTimeout},
		{credentialContext(protocol.CredentialManagementSubCommandDeleteCredential), ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, failure.CodeCredentialNotFound},
		{commandContext(protocol.AuthenticatorSelection), ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL, failure.CodeAuthenticatorSelectionCanceled},
		{commandContext(protocol.AuthenticatorSelection), ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeAuthenticatorSelectionTimeout},
		{commandContext(protocol.AuthenticatorSelection), ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeAuthenticatorSelectionTimeout},
		{commandContext(protocol.AuthenticatorLargeBlobs), ctaptransport.CTAP1_ERR_INVALID_SEQ, failure.CodeLargeBlobWriteSequenceInvalid},
		{commandContext(protocol.AuthenticatorLargeBlobs), ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE, failure.CodeLargeBlobIntegrityFailure},
		{configContext(protocol.ConfigSubCommandSetMinPINLength), ctaptransport.CTAP2_ERR_KEY_STORE_FULL, failure.CodeAuthenticatorConfigStorageFull},
	}

	for _, tt := range tests {
		if got := codeForCTAP(tt.status, tt.ctx); got != tt.code {
			t.Errorf("codeForCTAP(0x%02x, command 0x%02x) = %s, want %s", uint8(tt.status), uint8(tt.ctx.command), got, tt.code)
		}
	}
}

func TestNormalizeCommandOverrideProvenance(t *testing.T) {
	raw := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorGetNextAssertion,
		StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED,
	}
	err := Normalize(Annotate(raw, commandContext(
		protocol.AuthenticatorGetAssertion,
	)), "webauthn.getAssertion")
	assertFailure(
		t,
		err,
		failure.CodeAssertionContinuationUnavailable,
		"webauthn.getAssertion",
		failure.PhaseAssertionContinuation,
	)

	detail := failure.Snapshot(err).CTAP
	if detail == nil || detail.CommandCode != uint8(protocol.AuthenticatorGetNextAssertion) {
		t.Fatalf("CTAP detail = %#v, want getNextAssertion command", detail)
	}
	var gotRaw *ctaptransport.CTAPError
	if !errors.As(err, &gotRaw) || gotRaw != raw {
		t.Fatalf("raw CTAP error not preserved: %v", err)
	}
}

func TestNormalizeGeneralErrors(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		wrapped := fmt.Errorf("upstream canceled: %w", context.Canceled)
		err := Normalize(wrapped, "inspect")
		assertFailure(t, err, failure.CodeOperationCanceled, "inspect", "")
		if !errors.Is(err, context.Canceled) {
			t.Fatal("context.Canceled not preserved")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		wrapped := fmt.Errorf("upstream deadline: %w", context.DeadlineExceeded)
		err := Normalize(wrapped, "inspect")
		assertFailure(t, err, failure.CodeOperationTimeout, "inspect", "")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("context.DeadlineExceeded not preserved")
		}
	})

	t.Run("command annotated plain error is internal", func(t *testing.T) {
		raw := errors.New("opaque command failure")
		err := Normalize(Annotate(raw, WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorGetAssertion,
		)), "webauthn.getAssertion")
		assertFailure(
			t,
			err,
			failure.CodeInternalError,
			"webauthn.getAssertion",
			failure.PhaseAuthenticatorCommand,
		)
		if failure.Snapshot(err).CTAP != nil {
			t.Fatalf("plain command error acquired CTAP detail: %#v", failure.Snapshot(err).CTAP)
		}
		if !errors.Is(err, raw) {
			t.Fatal("plain command cause not preserved")
		}
	})

	t.Run("typed CTAPHID framing error is transport", func(t *testing.T) {
		err := Normalize(Annotate(ctaphid.ErrInvalidResponseMessage, WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorGetAssertion,
		)), "webauthn.getAssertion")
		assertFailure(
			t,
			err,
			failure.CodeTransportFailure,
			"webauthn.getAssertion",
			failure.PhaseAuthenticatorCommand,
		)
		if !errors.Is(err, ctaphid.ErrInvalidResponseMessage) {
			t.Fatal("CTAPHID framing sentinel not preserved")
		}
	})

	t.Run("unannotated internal error", func(t *testing.T) {
		raw := errors.New("opaque")
		err := Normalize(raw, "inspect")
		assertFailure(t, err, failure.CodeInternalError, "inspect", "")
		if !errors.Is(err, raw) {
			t.Fatal("opaque cause not preserved")
		}
	})

	t.Run("typed failure enrichment", func(t *testing.T) {
		raw := errors.New("invalid")
		typed := failure.Wrap(
			failure.CodeBioTemplateIDInvalid,
			raw,
			failure.WithPhase(failure.PhaseValidation),
		)
		err := Normalize(typed, "credentials.delete")
		assertFailure(t, err, failure.CodeBioTemplateIDInvalid, "credentials.delete", failure.PhaseValidation)
		if !errors.Is(err, raw) {
			t.Fatal("typed failure cause not preserved")
		}
	})

	t.Run("normalized failure cause does not override its code", func(t *testing.T) {
		existing := failure.Wrap(
			failure.CodeBioTemplateIDInvalid,
			context.Canceled,
			failure.WithOperation("credentials.delete"),
			failure.WithPhase(failure.PhaseValidation),
		)

		got := Normalize(existing, "credentials.delete")
		assertFailure(
			t,
			got,
			failure.CodeBioTemplateIDInvalid,
			"credentials.delete",
			failure.PhaseValidation,
		)
		if !errors.Is(got, context.Canceled) {
			t.Fatal("typed failure cause not preserved")
		}
	})
}

func TestUpstreamCode(t *testing.T) {
	tests := []struct {
		err  error
		ctx  errorContext
		code failure.Code
	}{
		{ctapdevice.ErrPinUvAuthTokenRequired, commandContext(protocol.AuthenticatorMakeCredential), failure.CodePINUVAuthTokenRequired},
		{ctapdevice.ErrPinNotSet, tokenContext(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions), failure.CodePINNotConfigured},
		{ctapdevice.ErrPinAlreadySet, WithClientPINSubCommand(failure.PhaseAuthenticatorCommand, protocol.ClientPINSubCommandSetPIN), failure.CodePINAlreadyConfigured},
		{ctapdevice.ErrBuiltInUVRequired, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeVerificationFlowUnsupported},
		{ctapdevice.ErrUvNotConfigured, tokenContext(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions), failure.CodeVerificationFlowUnsupported},
		{ctapdevice.ErrLargeBlobsIntegrityCheck, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobIntegrityFailure},
		{ctapdevice.SyntaxError, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobArrayInvalid},
		{ctapdevice.ErrLargeBlobsTooBig, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobArrayTooLarge},
		{ctapdevice.ErrInvalidSaltSize, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeCTAPParameterInvalid},
		{ctapdevice.SyntaxError, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeCTAPParameterInvalid},
		{ctapdevice.ErrSpecViolation, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeCTAPSpecViolation},
		{ctapdevice.ErrPingPongMismatch, WithPhase(failure.PhaseAuthenticatorCommand), failure.CodeTransportFailure},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorGetInfo), failure.CodeGetInfoUnsupported},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorClientPIN), failure.CodePINUnsupported},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorBioEnrollment), failure.CodeBioUnsupported},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorCredentialManagement), failure.CodeCredentialManagementUnsupported},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobUnsupported},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorConfig), failure.CodeAuthenticatorConfigUnsupported},
		{ctapdevice.ErrNotSupported, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeOperationUnsupported},
	}

	for _, tt := range tests {
		got, ok := upstreamCode(tt.err, tt.ctx)
		if !ok || got != tt.code {
			t.Errorf("upstreamCode(%v, command 0x%02x) = %s, %t; want %s, true", tt.err, uint8(tt.ctx.command), got, ok, tt.code)
		}
	}
}

func TestNormalizeUpstreamSentinel(t *testing.T) {
	raw := &ctapdevice.ErrorWithMessage{
		Message: "upstream detail",
		Err:     ctapdevice.ErrPinUvAuthTokenRequired,
	}
	err := Normalize(Annotate(raw, commandContext(
		protocol.AuthenticatorMakeCredential,
	)), "webauthn.makeCredential")
	assertFailure(
		t,
		err,
		failure.CodePINUVAuthTokenRequired,
		"webauthn.makeCredential",
		failure.PhaseAuthenticatorCommand,
	)
	if !errors.Is(err, ctapdevice.ErrPinUvAuthTokenRequired) {
		t.Fatal("upstream sentinel not preserved")
	}
}

func commandContext(command protocol.Command) errorContext {
	return WithCommand(failure.PhaseAuthenticatorCommand, command)
}

func tokenContext(subCommand protocol.ClientPINSubCommand) errorContext {
	return WithClientPINSubCommand(failure.PhaseTokenAcquisition, subCommand)
}

func bioContext(subCommand protocol.BioEnrollmentSubCommand) errorContext {
	return WithBioEnrollmentSubCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorBioEnrollment,
		subCommand,
	)
}

func credentialContext(subCommand protocol.CredentialManagementSubCommand) errorContext {
	return WithCredentialManagementSubCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorCredentialManagement,
		subCommand,
	)
}

func configContext(subCommand protocol.ConfigSubCommand) errorContext {
	return WithConfigSubCommand(failure.PhaseAuthenticatorCommand, subCommand)
}

func assertFailure(
	t *testing.T,
	err error,
	code failure.Code,
	operation string,
	phase failure.Phase,
) {
	t.Helper()

	snapshot := failure.Snapshot(err)
	if snapshot == nil {
		t.Fatal("failure snapshot = nil")
	}
	if snapshot.Code != code {
		t.Fatalf("failure code = %s, want %s", snapshot.Code, code)
	}
	if snapshot.Operation != operation {
		t.Fatalf("operation = %q, want %q", snapshot.Operation, operation)
	}
	if snapshot.Phase != phase {
		t.Fatalf("phase = %q, want %q", snapshot.Phase, phase)
	}
}
