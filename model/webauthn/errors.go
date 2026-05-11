package webauthn

import "errors"

var (
	ErrInvalidInput                  = errors.New("ctapkit: invalid WebAuthn input")
	ErrAttestedCredentialDataMissing = errors.New("ctapkit: attested credential data is missing")
	ErrConfirmationRequired          = errors.New("ctapkit: WebAuthn operation confirmation required")
)
