package workflow

import (
	"github.com/go-ctap/ctaphid/pkg/crypto"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func buildWriteMutation(state targetBlobState, payload []byte) ([]ctaptypes.LargeBlob, applargeblobs.MutationResult, error) {
	operation := applargeblobs.MutationCreate
	if state.currentBlobIndex >= 0 {
		operation = applargeblobs.MutationReplace
	}

	encrypted, err := crypto.EncryptLargeBlob(state.key, payload)
	if err != nil {
		return nil, applargeblobs.MutationResult{}, err
	}

	replacement := replaceBlob(state.blobs, state.currentBlobIndex, encrypted, operation)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return nil, applargeblobs.MutationResult{}, err
	}

	result := buildMutationResult(state, operation, len(payload), sizeAfter, false)
	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return nil, result, err
	}

	return replacement, result, nil
}

func buildDeleteMutation(state targetBlobState) ([]ctaptypes.LargeBlob, applargeblobs.MutationResult, bool, error) {
	if state.currentBlobIndex < 0 {
		return nil, buildMutationResult(state, applargeblobs.MutationNoBlob, 0, state.serializedArraySizeBefore, true), true, nil
	}

	replacement := removeBlobAt(state.blobs, state.currentBlobIndex)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return nil, applargeblobs.MutationResult{}, false, err
	}

	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return nil, applargeblobs.MutationResult{}, false, err
	}

	return replacement, buildMutationResult(state, applargeblobs.MutationDelete, 0, sizeAfter, false), false, nil
}
