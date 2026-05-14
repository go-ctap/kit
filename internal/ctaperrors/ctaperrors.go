package ctaperrors

import (
	"errors"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

type Domain string

const (
	DomainConfig      Domain = "config"
	DomainCredentials Domain = "credentials"
	DomainLargeBlobs  Domain = "large-blobs"
)

type SubCommandFamily string

const (
	SubCommandNone                 SubCommandFamily = ""
	SubCommandClientPIN            SubCommandFamily = "clientPIN"
	SubCommandBioEnrollment        SubCommandFamily = "bioEnrollment"
	SubCommandCredentialManagement SubCommandFamily = "credentialManagement"
	SubCommandLargeBlobs           SubCommandFamily = "largeBlobs"
	SubCommandConfig               SubCommandFamily = "config"
)

const (
	LargeBlobsSubCommandGet uint64 = 1
	LargeBlobsSubCommandSet uint64 = 2
)

type Context struct {
	Operation        model.OperationKind
	Command          protocol.Command
	SubCommandFamily SubCommandFamily
	SubCommand       uint64
	Domain           Domain
}

func WithClientPINSubCommand(operation model.OperationKind, subCommand protocol.ClientPINSubCommand) Context {
	return Context{
		Operation:        operation,
		Command:          protocol.AuthenticatorClientPIN,
		SubCommandFamily: SubCommandClientPIN,
		SubCommand:       uint64(subCommand),
		Domain:           DomainConfig,
	}
}

func WithBioEnrollmentSubCommand(operation model.OperationKind, command protocol.Command, subCommand protocol.BioEnrollmentSubCommand) Context {
	return Context{
		Operation:        operation,
		Command:          command,
		SubCommandFamily: SubCommandBioEnrollment,
		SubCommand:       uint64(subCommand),
		Domain:           DomainConfig,
	}
}

func WithCredentialManagementSubCommand(operation model.OperationKind, command protocol.Command, subCommand protocol.CredentialManagementSubCommand) Context {
	return Context{
		Operation:        operation,
		Command:          command,
		SubCommandFamily: SubCommandCredentialManagement,
		SubCommand:       uint64(subCommand),
		Domain:           DomainCredentials,
	}
}

func WithLargeBlobsSubCommand(operation model.OperationKind, subCommand uint64) Context {
	return Context{
		Operation:        operation,
		Command:          protocol.AuthenticatorLargeBlobs,
		SubCommandFamily: SubCommandLargeBlobs,
		SubCommand:       subCommand,
		Domain:           DomainLargeBlobs,
	}
}

func WithConfigSubCommand(operation model.OperationKind, subCommand protocol.ConfigSubCommand) Context {
	return Context{
		Operation:        operation,
		Command:          protocol.AuthenticatorConfig,
		SubCommandFamily: SubCommandConfig,
		SubCommand:       uint64(subCommand),
		Domain:           DomainConfig,
	}
}

func WithCommand(operation model.OperationKind, command protocol.Command, domain Domain) Context {
	return Context{
		Operation: operation,
		Command:   command,
		Domain:    domain,
	}
}

type annotatedError struct {
	err error
	ctx Context
}

func (e annotatedError) Error() string {
	return e.err.Error()
}

func (e annotatedError) Unwrap() error {
	return e.err
}

func Annotate(err error, ctx Context) error {
	if err == nil {
		return nil
	}

	if alreadyRuntimeError(err) {
		return err
	}

	if _, ok := errors.AsType[*ctaphid.CTAPError](err); !ok {
		return err
	}

	return annotatedError{err: err, ctx: ctx}
}

func Normalize(err error) error {
	if err == nil {
		return nil
	}

	if alreadyRuntimeError(err) {
		return err
	}

	ctapErr, ok := errors.AsType[*ctaphid.CTAPError](err)
	if !ok {
		return err
	}

	ctx := Context{}
	if annotated, ok := errors.AsType[annotatedError](err); ok {
		ctx = annotated.ctx
	}

	if ctx.Command == 0 {
		ctx.Command = ctapErr.Command
	} else if ctapErr.Command != 0 && ctapErr.Command != ctx.Command {
		ctx.Command = ctapErr.Command
		ctx.SubCommandFamily = SubCommandNone
		ctx.SubCommand = 0
	}

	if override, ok := commandRule(ctapErr.StatusCode, ctx); ok {
		return runtimeError(override, err)
	}

	return runtimeError(genericRule(ctapErr.StatusCode, ctx), err)
}

type rule struct {
	category model.ErrorCategory
	message  string
	sentinel error
}

func commandRule(status ctaphid.StatusCode, ctx Context) (rule, bool) {
	switch ctx.Command {
	case protocol.AuthenticatorMakeCredential:
		return makeCredentialRule(status, ctx)
	case protocol.AuthenticatorGetAssertion:
		return getAssertionRule(status, ctx)
	case protocol.AuthenticatorGetNextAssertion:
		return getNextAssertionRule(status, ctx)
	case protocol.AuthenticatorGetInfo:
		return getInfoRule(status, ctx)
	case protocol.AuthenticatorClientPIN:
		return clientPINRule(status, ctx)
	case protocol.AuthenticatorReset:
		return resetRule(status, ctx)
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		return bioEnrollmentRule(status, ctx)
	case protocol.AuthenticatorCredentialManagement, protocol.PrototypeAuthenticatorCredentialManagement:
		return credentialManagementRule(status, ctx)
	case protocol.AuthenticatorSelection:
		return selectionRule(status, ctx)
	case protocol.AuthenticatorLargeBlobs:
		return largeBlobsRule(status, ctx)
	case protocol.AuthenticatorConfig:
		return configRule(status, ctx)
	default:
		return rule{}, false
	}
}

func makeCredentialRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_CREDENTIAL_EXCLUDED:
		return invalidState("credential is excluded by the authenticator", appcredentials.ErrCredentialExcluded), true
	case ctaphid.CTAP2_ERR_KEY_STORE_FULL:
		return invalidState("authenticator credential storage is full", appcredentials.ErrCredentialStoreFull), true
	case ctaphid.CTAP2_ERR_OPERATION_DENIED:
		return invalidState("authenticator denied credential creation", appconfig.ErrOperationDenied), true
	}

	return rule{}, false
}

func getAssertionRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_NO_CREDENTIALS, ctaphid.CTAP2_ERR_INVALID_CREDENTIAL:
		return invalidState("authenticator found no matching credentials", appcredentials.ErrCredentialNotFound), true
	case ctaphid.CTAP2_ERR_OPERATION_DENIED:
		return invalidState("authenticator denied assertion", appconfig.ErrOperationDenied), true
	}

	return rule{}, false
}

func getNextAssertionRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_NOT_ALLOWED:
		return invalidState("authenticator has no pending assertion continuation", nil), true
	}

	return rule{}, false
}

func getInfoRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP1_ERR_INVALID_COMMAND:
		return unsupported("authenticator does not support CTAP getInfo", nil), true
	}

	return rule{}, false
}

func clientPINRule(status ctaphid.StatusCode, ctx Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_PIN_INVALID:
		return invalidState("PIN is invalid", appconfig.ErrPINInvalid), true
	case ctaphid.CTAP2_ERR_PIN_BLOCKED:
		return invalidState("PIN is blocked", appconfig.ErrPINBlocked), true
	case ctaphid.CTAP2_ERR_PIN_AUTH_INVALID:
		return clientPINAuthInvalidRule(ctx), true
	case ctaphid.CTAP2_ERR_PIN_AUTH_BLOCKED:
		return invalidState("PIN/UV auth is temporarily blocked; power-cycle the authenticator before retrying", appconfig.ErrPINAuthBlocked), true
	case ctaphid.CTAP2_ERR_PIN_NOT_SET:
		return invalidState("PIN is not configured", appconfig.ErrPINNotConfigured), true
	case ctaphid.CTAP2_ERR_PUAT_REQUIRED:
		return invalidState("pinUvAuthToken is required", appconfig.ErrPinUvAuthRequired), true
	case ctaphid.CTAP2_ERR_PIN_POLICY_VIOLATION:
		return invalidState("PIN policy violation", appconfig.ErrPINPolicyViolation), true
	case ctaphid.CTAP2_ERR_UV_BLOCKED:
		return invalidState("user verification is blocked", appconfig.ErrUserVerificationBlocked), true
	case ctaphid.CTAP2_ERR_UV_INVALID:
		return invalidState("user verification failed", appconfig.ErrUserVerificationInvalid), true
	case ctaphid.CTAP2_ERR_UP_REQUIRED:
		return invalidState("user presence is required", appconfig.ErrUserPresenceRequired), true
	case ctaphid.CTAP2_ERR_UNAUTHORIZED_PERMISSION:
		return invalidState("pinUvAuthToken permission is unauthorized", appconfig.ErrPINAuthInvalid), true
	case ctaphid.CTAP2_ERR_OPERATION_DENIED:
		return invalidState("authenticator denied PIN/UV operation", appconfig.ErrOperationDenied), true
	}

	return rule{}, false
}

func clientPINAuthInvalidRule(ctx Context) rule {
	switch protocol.ClientPINSubCommand(ctx.SubCommand) {
	case protocol.ClientPINSubCommandSetPIN:
		return invalidState("PIN is already configured or PIN/UV auth verification failed", errors.Join(appconfig.ErrPINAlreadyConfigured, appconfig.ErrPINAuthInvalid))
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		protocol.ClientPINSubCommandGetPinToken:
		return invalidState("PIN/UV auth verification failed", appconfig.ErrPINAuthInvalid)
	default:
		return invalidState("PIN/UV auth verification failed", appconfig.ErrPINAuthInvalid)
	}
}

func resetRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_NOT_ALLOWED:
		return rule{
			category: model.ErrorInvalidState,
			message:  "factory reset must be requested shortly after authenticator power-up; power-cycle or reconnect the authenticator and retry promptly",
			sentinel: appconfig.ErrResetWindowExpired,
		}, true
	case ctaphid.CTAP2_ERR_USER_ACTION_TIMEOUT, ctaphid.CTAP2_ERR_ACTION_TIMEOUT:
		return timeout("timed out waiting for authenticator touch during factory reset", nil), true
	case ctaphid.CTAP2_ERR_OPERATION_DENIED:
		return invalidState("authenticator denied factory reset", appconfig.ErrOperationDenied), true
	}

	return rule{}, false
}

func bioEnrollmentRule(status ctaphid.StatusCode, ctx Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_FP_DATABASE_FULL:
		return invalidState("biometric enrollment database is full", appconfig.ErrBioDatabaseFull), true
	case ctaphid.CTAP2_ERR_INVALID_OPTION:
		return bioInvalidOptionRule(ctx), true
	case ctaphid.CTAP2_ERR_PUAT_REQUIRED:
		return invalidState("pinUvAuthToken is required for biometric enrollment", appconfig.ErrPinUvAuthRequired), true
	case ctaphid.CTAP2_ERR_PIN_AUTH_INVALID:
		return invalidState("biometric enrollment token is invalid or unauthorized", appconfig.ErrPINAuthInvalid), true
	case ctaphid.CTAP2_ERR_OPERATION_DENIED:
		return invalidState("authenticator denied biometric enrollment operation", appconfig.ErrOperationDenied), true
	case ctaphid.CTAP2_ERR_USER_ACTION_TIMEOUT, ctaphid.CTAP2_ERR_ACTION_TIMEOUT:
		return timeout("timed out waiting for biometric enrollment interaction", nil), true
	}

	return rule{}, false
}

func bioInvalidOptionRule(ctx Context) rule {
	switch protocol.BioEnrollmentSubCommand(ctx.SubCommand) {
	case protocol.BioEnrollmentSubCommandEnumerateEnrollments:
		return invalidState("authenticator has no biometric enrollments", appconfig.ErrBioNoEnrollments)
	case protocol.BioEnrollmentSubCommandSetFriendlyName,
		protocol.BioEnrollmentSubCommandRemoveEnrollment:
		return invalidState("biometric enrollment was not found", appconfig.ErrBioEnrollmentNotFound)
	default:
		return invalidState("invalid biometric enrollment option", nil)
	}
}

func credentialManagementRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_NO_CREDENTIALS, ctaphid.CTAP2_ERR_INVALID_CREDENTIAL:
		return invalidState("authenticator found no matching resident credentials", appcredentials.ErrCredentialNotFound), true
	case ctaphid.CTAP2_ERR_KEY_STORE_FULL:
		return invalidState("authenticator credential storage is full", appcredentials.ErrCredentialStoreFull), true
	case ctaphid.CTAP2_ERR_PUAT_REQUIRED:
		return invalidState("pinUvAuthToken is required for credential management", appconfig.ErrPinUvAuthRequired), true
	case ctaphid.CTAP2_ERR_PIN_AUTH_INVALID:
		return invalidState("credential management token is invalid or unauthorized", appconfig.ErrPINAuthInvalid), true
	}

	return rule{}, false
}

func selectionRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_KEEPALIVE_CANCEL:
		return canceled("authenticator selection was canceled", nil), true
	case ctaphid.CTAP2_ERR_USER_ACTION_TIMEOUT, ctaphid.CTAP2_ERR_ACTION_TIMEOUT:
		return timeout("timed out waiting for authenticator selection", nil), true
	}

	return rule{}, false
}

func largeBlobsRule(status ctaphid.StatusCode, _ Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL:
		return invalidState("authenticator large blob storage is full", applargeblobs.ErrLargeBlobStorageFull), true
	case ctaphid.CTAP1_ERR_INVALID_SEQ:
		return invalidOperation("invalid large blob write sequence", applargeblobs.ErrLargeBlobWriteSequence), true
	case ctaphid.CTAP2_ERR_INTEGRITY_FAILURE:
		return invalidState("large blob array integrity check failed", applargeblobs.ErrLargeBlobIntegrity), true
	case ctaphid.CTAP2_ERR_PIN_AUTH_INVALID:
		return invalidState("large blob write token is invalid or unauthorized", appconfig.ErrPINAuthInvalid), true
	case ctaphid.CTAP2_ERR_PUAT_REQUIRED:
		return invalidState("pinUvAuthToken is required for large blob write", appconfig.ErrPinUvAuthRequired), true
	}

	return rule{}, false
}

func configRule(status ctaphid.StatusCode, ctx Context) (rule, bool) {
	switch status {
	case ctaphid.CTAP2_ERR_OPERATION_DENIED:
		if protocol.ConfigSubCommand(ctx.SubCommand) == protocol.ConfigSubCommandToggleAlwaysUv {
			return invalidState("authenticator does not allow disabling alwaysUv", appconfig.ErrOperationDenied), true
		}

		return invalidState("authenticator denied configuration operation", appconfig.ErrOperationDenied), true
	case ctaphid.CTAP2_ERR_PIN_POLICY_VIOLATION:
		return invalidState("PIN policy violation", appconfig.ErrPINPolicyViolation), true
	case ctaphid.CTAP2_ERR_PIN_NOT_SET:
		return invalidState("PIN is not configured", appconfig.ErrPINNotConfigured), true
	case ctaphid.CTAP2_ERR_KEY_STORE_FULL:
		return invalidState("authenticator configuration storage is full", appconfig.ErrAuthenticatorConfigStorageFull), true
	case ctaphid.CTAP2_ERR_PUAT_REQUIRED:
		return invalidState("pinUvAuthToken is required for authenticator configuration", appconfig.ErrPinUvAuthRequired), true
	case ctaphid.CTAP2_ERR_PIN_AUTH_INVALID:
		return invalidState("authenticator configuration token is invalid or unauthorized", appconfig.ErrPINAuthInvalid), true
	}

	return rule{}, false
}

func genericRule(status ctaphid.StatusCode, _ Context) rule {
	switch status {
	case ctaphid.CTAP1_ERR_INVALID_COMMAND,
		ctaphid.CTAP2_ERR_UNSUPPORTED_ALGORITHM,
		ctaphid.CTAP2_ERR_UNSUPPORTED_OPTION,
		ctaphid.CTAP2_ERR_INVALID_SUBCOMMAND:
		return unsupported("authenticator does not support the requested CTAP command or option", nil)
	case ctaphid.CTAP1_ERR_INVALID_PARAMETER,
		ctaphid.CTAP1_ERR_INVALID_LENGTH,
		ctaphid.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
		ctaphid.CTAP2_ERR_INVALID_CBOR,
		ctaphid.CTAP2_ERR_MISSING_PARAMETER,
		ctaphid.CTAP2_ERR_LIMIT_EXCEEDED,
		ctaphid.CTAP2_ERR_REQUEST_TOO_LARGE,
		ctaphid.CTAP2_ERR_INVALID_OPTION:
		return invalidOperation("authenticator rejected invalid CTAP request parameters", nil)
	case ctaphid.CTAP1_ERR_TIMEOUT,
		ctaphid.CTAP2_ERR_USER_ACTION_TIMEOUT,
		ctaphid.CTAP2_ERR_ACTION_TIMEOUT:
		return timeout("CTAP operation timed out", nil)
	case ctaphid.CTAP1_ERR_CHANNEL_BUSY,
		ctaphid.CTAP2_ERR_PROCESSING,
		ctaphid.CTAP2_ERR_USER_ACTION_PENDING,
		ctaphid.CTAP2_ERR_OPERATION_PENDING:
		return busy("authenticator is busy processing another operation", nil)
	case ctaphid.CTAP2_ERR_KEEPALIVE_CANCEL:
		return canceled("CTAP operation was canceled", nil)
	case ctaphid.CTAP2_ERR_NO_OPERATIONS,
		ctaphid.CTAP2_ERR_NOT_ALLOWED,
		ctaphid.CTAP2_ERR_OPERATION_DENIED,
		ctaphid.CTAP2_ERR_INVALID_CREDENTIAL,
		ctaphid.CTAP2_ERR_PIN_INVALID,
		ctaphid.CTAP2_ERR_PIN_BLOCKED,
		ctaphid.CTAP2_ERR_PIN_AUTH_INVALID,
		ctaphid.CTAP2_ERR_PIN_AUTH_BLOCKED,
		ctaphid.CTAP2_ERR_PIN_NOT_SET,
		ctaphid.CTAP2_ERR_PUAT_REQUIRED,
		ctaphid.CTAP2_ERR_PIN_POLICY_VIOLATION,
		ctaphid.CTAP2_ERR_UP_REQUIRED,
		ctaphid.CTAP2_ERR_UV_BLOCKED,
		ctaphid.CTAP2_ERR_UV_INVALID,
		ctaphid.CTAP2_ERR_UNAUTHORIZED_PERMISSION,
		ctaphid.CTAP2_ERR_CREDENTIAL_EXCLUDED,
		ctaphid.CTAP2_ERR_NO_CREDENTIALS,
		ctaphid.CTAP2_ERR_KEY_STORE_FULL,
		ctaphid.CTAP2_ERR_FP_DATABASE_FULL,
		ctaphid.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL:
		return invalidState("authenticator rejected the CTAP operation in its current state", nil)
	case ctaphid.CTAP1_ERR_INVALID_SEQ,
		ctaphid.CTAP1_ERR_LOCK_REQUIRED,
		ctaphid.CTAP1_ERR_INVALID_CHANNEL,
		ctaphid.CTAP1_ERR_OTHER,
		ctaphid.CTAP2_ERR_INTEGRITY_FAILURE:
		return transportFailure("CTAP transport or framing failure", nil)
	default:
		if status >= ctaphid.CTAP2_ERR_SPEC_LAST {
			return transportFailure("CTAP command failed with reserved or vendor status", nil)
		}

		return transportFailure("CTAP command failed", nil)
	}
}

func runtimeError(r rule, cause error) error {
	err := cause
	if r.sentinel != nil {
		err = errors.Join(r.sentinel, cause)
	}

	return model.NewRuntimeError(r.category, r.message, err)
}

func unsupported(message string, sentinel error) rule {
	return rule{category: model.ErrorUnsupported, message: message, sentinel: sentinel}
}

func invalidOperation(message string, sentinel error) rule {
	return rule{category: model.ErrorInvalidOperation, message: message, sentinel: sentinel}
}

func invalidState(message string, sentinel error) rule {
	return rule{category: model.ErrorInvalidState, message: message, sentinel: sentinel}
}

func timeout(message string, sentinel error) rule {
	return rule{category: model.ErrorTimeout, message: message, sentinel: sentinel}
}

func busy(message string, sentinel error) rule {
	return rule{category: model.ErrorBusy, message: message, sentinel: sentinel}
}

func canceled(message string, sentinel error) rule {
	return rule{category: model.ErrorCanceled, message: message, sentinel: sentinel}
}

func transportFailure(message string, sentinel error) rule {
	return rule{category: model.ErrorTransportFailure, message: message, sentinel: sentinel}
}

func alreadyRuntimeError(err error) bool {
	_, ok := errors.AsType[*model.RuntimeError](err)
	return ok
}
