package workflow

import (
	"context"
	"slices"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/secret"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/report"
)

type targetBlobState struct {
	selected                  report.DeviceReport
	support                   applargeblobs.SupportReport
	target                    appcredentials.CredentialTarget
	key                       []byte
	blobs                     []protocol.LargeBlob
	currentBlobIndex          int
	currentBytes              []byte
	serializedArraySizeBefore int
}

func (r Runner) loadTargetBlobState(
	ctx context.Context,
	inventory appcredentials.InventoryReport,
	credentialIDHex string,
) (targetBlobState, error) {
	target, err := appcredentials.FindCredentialByHexID(inventory, credentialIDHex)
	if err != nil {
		return targetBlobState{}, err
	}

	support := buildLargeBlobSupportReport(r.env.Authenticator.GetInfo())
	if !support.LargeBlobs {
		return targetBlobState{}, failure.New(failure.CodeLargeBlobUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	if len(target.Record.LargeBlobKey) == 0 {
		return targetBlobState{}, failure.New(failure.CodeLargeBlobKeyMissing,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	key := slices.Clone(target.Record.LargeBlobKey)

	blobs, err := r.readLargeBlobArray(ctx)
	if err != nil {
		secret.Zero(key)

		return targetBlobState{}, err
	}

	sizeBefore, err := serializedLargeBlobArraySize(blobs)
	if err != nil {
		secret.Zero(key)

		return targetBlobState{}, err
	}

	state := targetBlobState{
		selected:                  r.env.Selected,
		support:                   support,
		target:                    target,
		key:                       key,
		blobs:                     cloneLargeBlobs(blobs),
		currentBlobIndex:          -1,
		serializedArraySizeBefore: sizeBefore,
	}

	for index, candidate := range blobs {
		raw, err := crypto.DecryptLargeBlob(key, candidate)
		if err != nil {
			continue
		}

		state.currentBlobIndex = index

		state.currentBytes = slices.Clone(raw)
		secret.Zero(raw)

		break
	}

	return state, nil
}

func (state *targetBlobState) zero() {
	secret.Zero(state.key)
	secret.Zero(state.currentBytes)
}
