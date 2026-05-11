package workflow

import (
	"fmt"
	"slices"

	"github.com/go-ctap/ctaphid/pkg/crypto"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/kit/internal/secret"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/report"
)

type targetBlobState struct {
	selected                  report.DeviceReport
	support                   applargeblobs.SupportReport
	target                    appcredentials.CredentialTarget
	key                       []byte
	blobs                     []ctaptypes.LargeBlob
	currentBlobIndex          int
	currentBytes              []byte
	serializedArraySizeBefore int
}

func (r Runner) loadTargetBlobState(
	inventory appcredentials.InventoryReport,
	credentialIDHex string,
) (targetBlobState, error) {
	target, err := appcredentials.FindCredentialByHexID(inventory, credentialIDHex)
	if err != nil {
		return targetBlobState{}, err
	}

	authenticator := r.largeBlobManager()
	support := buildLargeBlobSupportReport(authenticator.GetInfo())
	if !support.LargeBlobs {
		return targetBlobState{}, fmt.Errorf("%w: device does not support large blobs", applargeblobs.ErrUnsupportedLargeBlobs)
	}

	if len(target.Record.LargeBlobKey) == 0 {
		return targetBlobState{}, fmt.Errorf("%w: selected credential has no largeBlobKey", applargeblobs.ErrLargeBlobKeyMissing)
	}

	key := slices.Clone(target.Record.LargeBlobKey)

	blobs, err := r.readLargeBlobArray()
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
