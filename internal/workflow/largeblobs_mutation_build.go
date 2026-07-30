package workflow

import (
	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

type largeBlobMutationPlan struct {
	replacement []protocol.LargeBlob
	operation   applargeblobs.MutationOperation
	byteCount   int
	sizeAfter   int
	noop        bool
}

func buildWriteMutationPlan(state targetBlobState, payload []byte) (largeBlobMutationPlan, error) {
	operation := applargeblobs.MutationCreate
	if state.currentBlobIndex >= 0 {
		operation = applargeblobs.MutationReplace
	}

	encrypted, err := crypto.EncryptLargeBlob(state.key, payload)
	if err != nil {
		return largeBlobMutationPlan{}, err
	}

	replacement := replaceBlob(state.blobs, state.currentBlobIndex, encrypted, operation)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return largeBlobMutationPlan{}, err
	}

	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return largeBlobMutationPlan{}, err
	}

	return largeBlobMutationPlan{
		replacement: replacement,
		operation:   operation,
		byteCount:   len(payload),
		sizeAfter:   sizeAfter,
	}, nil
}

func buildDeleteMutationPlan(state targetBlobState) (largeBlobMutationPlan, error) {
	if state.currentBlobIndex < 0 {
		return largeBlobMutationPlan{
			operation: applargeblobs.MutationNoBlob,
			sizeAfter: state.serializedArraySizeBefore,
			noop:      true,
		}, nil
	}

	replacement := removeBlobAt(state.blobs, state.currentBlobIndex)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return largeBlobMutationPlan{}, err
	}

	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return largeBlobMutationPlan{}, err
	}

	return largeBlobMutationPlan{
		replacement: replacement,
		operation:   applargeblobs.MutationDelete,
		sizeAfter:   sizeAfter,
	}, nil
}

func (plan largeBlobMutationPlan) result(state targetBlobState) applargeblobs.MutationResult {
	return buildMutationResult(
		state,
		plan.operation,
		plan.byteCount,
		plan.sizeAfter,
		plan.noop,
	)
}
