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

type LargeBlobDevice = authenticator.LargeBlobDevice
type ConfigStatusDevice = authenticator.ConfigStatusDevice
type ConfigDevice = authenticator.ConfigDevice
type BioDevice = authenticator.BioDevice
