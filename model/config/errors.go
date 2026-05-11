package config

import "errors"

var (
	ErrConfirmationRequired = errors.New("ctapkit: config mutation confirmation required")

	ErrPINUnsupported          = errors.New("ctapkit: PIN is unsupported")
	ErrPINAlreadyConfigured    = errors.New("ctapkit: PIN is already configured")
	ErrPINNotConfigured        = errors.New("ctapkit: PIN is not configured")
	ErrPINRequired             = errors.New("ctapkit: PIN is required")
	ErrPINInvalid              = errors.New("ctapkit: PIN is invalid")
	ErrPINBlocked              = errors.New("ctapkit: PIN is blocked")
	ErrPINAuthInvalid          = errors.New("ctapkit: PIN/UV auth verification failed")
	ErrPINAuthBlocked          = errors.New("ctapkit: PIN/UV auth is temporarily blocked")
	ErrPINPolicyViolation      = errors.New("ctapkit: PIN policy violation")
	ErrPinUvAuthRequired       = errors.New("ctapkit: pinUvAuthToken is required")
	ErrUserVerificationBlocked = errors.New("ctapkit: user verification is blocked")
	ErrUserVerificationInvalid = errors.New("ctapkit: user verification failed")
	ErrUserPresenceRequired    = errors.New("ctapkit: user presence is required")
	ErrOperationDenied         = errors.New("ctapkit: operation denied by authenticator")

	ErrBioUnsupported        = errors.New("ctapkit: biometric enrollment is unsupported")
	ErrBioEnrollmentFailed   = errors.New("ctapkit: biometric enrollment failed")
	ErrBioTemplateID         = errors.New("ctapkit: invalid biometric template ID")
	ErrBioNoEnrollments      = errors.New("ctapkit: no biometric enrollments")
	ErrBioEnrollmentNotFound = errors.New("ctapkit: biometric enrollment not found")
	ErrBioDatabaseFull       = errors.New("ctapkit: biometric database full")

	ErrAuthenticatorConfigUnsupported = errors.New("ctapkit: authenticator config is unsupported")
	ErrAuthenticatorConfigStorageFull = errors.New("ctapkit: authenticator config storage full")
	ErrAlwaysUVStateUnknown           = errors.New("ctapkit: alwaysUv current state is unknown")
	ErrAlwaysUVAlreadyTarget          = errors.New("ctapkit: alwaysUv already matches requested target")
	ErrMinPINLengthUnsupported        = errors.New("ctapkit: min PIN length configuration is unsupported")
	ErrMinPINLengthLowering           = errors.New("ctapkit: requested value is less than current min PIN length")
	ErrResetWindowExpired             = errors.New("ctapkit: factory reset request window expired")
)
