package workflow

import (
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model"
)

type Effects struct {
	InvalidateAll                  bool
	InvalidateCredentials          bool
	InvalidateLargeBlobs           bool
	InvalidateConfig               bool
	InvalidateToken                bool
	ClearTokenUnlessLargeBlobWrite bool
}

func (e Effects) Apply(cache CacheStore) {
	if cache == nil {
		return
	}

	if e.InvalidateAll {
		cache.InvalidateAll()

		return
	}

	if e.InvalidateCredentials {
		cache.InvalidateCredentials()
	}
	if e.InvalidateLargeBlobs {
		cache.InvalidateLargeBlobs()
	}
	if e.InvalidateConfig {
		cache.InvalidateConfig()
	}
	if e.InvalidateToken {
		cache.InvalidateToken()
	}
	if e.ClearTokenUnlessLargeBlobWrite {
		cache.InvalidateTokenUnlessPermission(protocol.PermissionLargeBlobWrite)
	}
}

type dryRunOperation interface {
	IsDryRun() bool
}

func skipDryRun(op dryRunOperation, effects Effects) Effects {
	if op.IsDryRun() {
		return Effects{}
	}

	return effects
}

func credentialMutationEffects(op dryRunOperation) Effects {
	return skipDryRun(op, Effects{
		InvalidateCredentials: true,
	})
}

func largeBlobMutationEffects(op dryRunOperation) Effects {
	return skipDryRun(op, Effects{
		InvalidateLargeBlobs: true,
	})
}

func largeBlobMutationResultEffects(op dryRunOperation, result model.OperationResult) Effects {
	output, ok := result.(model.LargeBlobMutationOutput)
	if !ok {
		return Effects{}
	}
	if output.Result == nil || output.Result.NoBlob || output.Result.Noop {
		return Effects{}
	}

	return largeBlobMutationEffects(op)
}

func resetEffects(op dryRunOperation) Effects {
	return skipDryRun(op, Effects{
		InvalidateAll: true,
	})
}

func pinMutationEffects(op dryRunOperation) Effects {
	return skipDryRun(op, Effects{
		InvalidateConfig: true,
		InvalidateToken:  true,
	})
}

func bioMutationEffects(op dryRunOperation) Effects {
	return skipDryRun(op, Effects{
		InvalidateConfig: true,
	})
}

func authenticatorConfigEffects(op dryRunOperation) Effects {
	return skipDryRun(op, Effects{
		InvalidateConfig: true,
	})
}

func makeCredentialEffects(op dryRunOperation, output model.MakeCredentialOutput) Effects {
	effects := credentialMutationEffects(op)
	if output.Result != nil && output.Result.UserPresent {
		effects.ClearTokenUnlessLargeBlobWrite = true
	}

	return effects
}

func getAssertionEffects(op model.GetAssertionOperation, output model.GetAssertionOutput) Effects {
	effects := Effects{}
	if hasLargeBlobWrite(op.Extensions) && !op.DryRun {
		effects.InvalidateLargeBlobs = true
	}
	if output.Result == nil {
		return effects
	}
	for _, assertion := range output.Result.Assertions {
		if assertion.UserPresent {
			effects.ClearTokenUnlessLargeBlobWrite = true

			return effects
		}
	}

	return effects
}
