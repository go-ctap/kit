package workflow

import (
	"github.com/go-ctap/ctap/crypto"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/safety"
)

const sharedArrayRewriteWarning = "CTAP updates one credential's blob by rewriting the authenticator's entire shared serialized large-blob array."

func buildWritePreviewFromState(state targetBlobState, payload []byte) (applargeblobs.MutationPreview, error) {
	operation := applargeblobs.MutationCreate
	if state.currentBlobIndex >= 0 {
		operation = applargeblobs.MutationReplace
	}

	proposedSize, err := estimateSerializedArraySize(state, payload, operation)
	if err != nil {
		return applargeblobs.MutationPreview{}, err
	}

	preview := buildMutationPreview(state, operation, len(payload), proposedSize, false)
	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, proposedSize); err != nil {
		return preview, err
	}

	return preview, nil
}

func buildDeletePreviewFromState(state targetBlobState) (applargeblobs.MutationPreview, error) {
	operation := applargeblobs.MutationDelete
	noBlob := false

	proposedSize := state.serializedArraySizeBefore
	if state.currentBlobIndex < 0 {
		operation = applargeblobs.MutationNoBlob
		noBlob = true
	} else {
		blobs := removeBlobAt(state.blobs, state.currentBlobIndex)

		var err error

		proposedSize, err = serializedLargeBlobArraySize(blobs)
		if err != nil {
			return applargeblobs.MutationPreview{}, err
		}
	}

	return buildMutationPreview(state, operation, 0, proposedSize, noBlob), nil
}

func estimateSerializedArraySize(state targetBlobState, payload []byte, operation applargeblobs.MutationOperation) (int, error) {
	blob, err := crypto.EncryptLargeBlob(state.key, payload)
	if err != nil {
		return 0, err
	}

	replacement := replaceBlob(state.blobs, state.currentBlobIndex, blob, operation)

	size, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return 0, err
	}

	return size, nil
}

func buildMutationPreview(
	state targetBlobState,
	operation applargeblobs.MutationOperation,
	proposedByteCount int,
	sizeAfter int,
	noBlob bool,
) applargeblobs.MutationPreview {
	blobCountAfter := len(state.blobs)

	switch operation {
	case applargeblobs.MutationCreate:
		blobCountAfter++
	case applargeblobs.MutationDelete:
		blobCountAfter--
	}

	if blobCountAfter < 0 {
		blobCountAfter = 0
	}

	warnings := []safety.Warning{
		{
			Severity: safety.SeverityWarning,
			Code:     "large_blob.shared_array_rewrite",
			Message:  sharedArrayRewriteWarning,
		},
	}

	switch operation {
	case applargeblobs.MutationReplace:
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     "large_blob.replace_existing",
			Message:  "The first large-blob entry decryptable with this credential's largeBlobKey will be replaced; any additional matching entries remain unchanged.",
		})
	case applargeblobs.MutationDelete:
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityDestructive,
			Code:     "large_blob.delete_existing",
			Message:  "The first large-blob entry decryptable with this credential's largeBlobKey will be deleted; any additional matching entries remain unchanged.",
		})
	case applargeblobs.MutationNoBlob:
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityInfo,
			Code:     "large_blob.delete_noop",
			Message:  "No large blob exists for this credential; delete is a no-op.",
		})
	}

	return applargeblobs.MutationPreview{
		Operation:                          operation,
		Device:                             state.selected,
		Support:                            state.support,
		Target:                             buildBlobTarget(state.target),
		LargeBlobKeyState:                  applargeblobs.LargeBlobKeyAvailable,
		CurrentByteCount:                   len(state.currentBytes),
		ProposedByteCount:                  proposedByteCount,
		SerializedLargeBlobArraySizeBefore: state.serializedArraySizeBefore,
		SerializedLargeBlobArraySizeAfter:  sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     blobCountAfter,
		NoBlob:                             noBlob,
		Warnings:                           warnings,
	}
}
