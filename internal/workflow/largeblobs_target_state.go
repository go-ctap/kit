package workflow

import (
	"context"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	rtcredentials "github.com/go-ctap/kit/internal/credentials"
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
	device LargeBlobDevice,
	inventory *largeBlobInventory,
	credentialIDHex string,
) (targetBlobState, error) {
	if err := ctx.Err(); err != nil {
		return targetBlobState{}, err
	}

	target, err := rtcredentials.FindByHexID(inventory.credentials, credentialIDHex)
	if err != nil {
		return targetBlobState{}, err
	}

	support := buildLargeBlobSupportReport(device.GetInfo())
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

	key := target.Record.LargeBlobKey

	sizeBefore, err := serializedLargeBlobArraySize(inventory.blobs)
	if err != nil {
		return targetBlobState{}, err
	}

	state := targetBlobState{
		selected:                  r.env.Selected,
		support:                   support,
		target:                    target,
		key:                       key,
		blobs:                     inventory.blobs,
		currentBlobIndex:          -1,
		serializedArraySizeBefore: sizeBefore,
	}

	for index, candidate := range inventory.blobs {
		raw, err := crypto.DecryptLargeBlob(key, candidate)
		if err != nil {
			continue
		}

		state.currentBlobIndex = index
		state.currentBytes = raw

		break
	}

	return state, nil
}

func (state *targetBlobState) zero() {
	secret.Zero(state.currentBytes)
}
