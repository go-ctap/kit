package credentials

import "errors"

var (
	ErrUnsupportedCredentialManagement = errors.New("ctapkit: unsupported credential management")
	ErrCredentialNotFound              = errors.New("ctapkit: credential not found")
	ErrCredentialExcluded              = errors.New("ctapkit: credential excluded")
	ErrCredentialStoreFull             = errors.New("ctapkit: credential store full")
	ErrConfirmationRequired            = errors.New("ctapkit: confirmation required")
	ErrNoCredentialChanges             = errors.New("ctapkit: no credential changes requested")
	ErrInvalidUserIDHex                = errors.New("ctapkit: invalid user id hex")
)
