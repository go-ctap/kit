package workflow

import (
	"github.com/go-ctap/kit/internal/authenticator"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
)

type Runner struct {
	env Environment
}

func NewRunner(env Environment) Runner {
	return Runner{env: env}
}

func (r Runner) recordStateEffect(effect rtruntime.StateEffect) {
	r.env.Effects.Record(effect)
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
