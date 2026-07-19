package workflow

import "github.com/go-ctap/kit/internal/authenticator"

type Runner struct {
	env Environment
}

func NewRunner(env Environment) Runner {
	return Runner{env: env}
}

type LargeBlobDevice interface {
	authenticator.CredentialInventoryReader
	authenticator.LargeBlobManager
}

type ConfigStatusDevice interface {
	authenticator.InfoProvider
	authenticator.RetryProvider
}

type ConfigDevice interface {
	ConfigStatusDevice
	authenticator.ConfigManager
}

type BioDevice interface {
	ConfigStatusDevice
	authenticator.BioEnrollmentManager
}
