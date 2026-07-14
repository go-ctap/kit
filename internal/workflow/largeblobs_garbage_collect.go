package workflow

import (
	"context"
	"slices"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	"github.com/go-ctap/kit/model"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/safety"
)

type garbageCollectState struct {
	support        applargeblobs.SupportReport
	blobs          []protocol.LargeBlob
	replacement    []protocol.LargeBlob
	matchedCount   int
	unmatchedCount int
	sizeBefore     int
	sizeAfter      int
}

func (r Runner) garbageCollectLargeBlobs(ctx context.Context, req model.GarbageCollectLargeBlobsOperation) (model.OperationResult, error) {
	var output model.LargeBlobMutationOutput

	state, err := r.loadGarbageCollectState(ctx)
	if err != nil {
		return output, err
	}

	preview := r.buildGarbageCollectPreview(state)
	output.Preview = preview
	if req.DryRun {
		return output, nil
	}

	if err := r.confirmMutation(ctx, confirmationRequest{
		confirmed:       req.Confirmed,
		message:         req.ConfirmationMessage,
		fallbackMessage: "Garbage collect unmatched large blob entries?",
		destructive:     true,
		preview:         preview,
	}); err != nil {
		return output, err
	}

	result := r.buildGarbageCollectResult(state)
	if state.unmatchedCount == 0 {
		output.Result = &result

		return output, nil
	}

	token, err := r.env.Tokens.Acquire(ctx, r.tokenProvider(), protocol.PermissionLargeBlobWrite, "")
	if err != nil {
		return output, err
	}
	defer secret.Zero(token)

	if err := r.largeBlobManager().SetLargeBlobs(ctx, token, state.replacement); err != nil {
		return output, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	output.Result = &result

	return output, nil
}

func (r Runner) loadGarbageCollectState(ctx context.Context) (garbageCollectState, error) {
	inventory, err := r.readCredentialInventoryReport(ctx)
	if err != nil {
		return garbageCollectState{}, err
	}
	defer zeroCredentialInventoryReport(&inventory)

	support := buildLargeBlobSupportReport(r.largeBlobManager().GetInfo())
	if !support.LargeBlobs {
		return garbageCollectState{}, failure.New(failure.CodeLargeBlobUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	blobs, err := r.readLargeBlobArray(ctx)
	if err != nil {
		return garbageCollectState{}, err
	}

	sizeBefore, err := serializedLargeBlobArraySize(blobs)
	if err != nil {
		return garbageCollectState{}, err
	}

	keys := largeBlobKeys(inventory)
	replacement := make([]protocol.LargeBlob, 0, len(blobs))
	var matchedCount, unmatchedCount int
	for _, blob := range blobs {
		if !largeBlobMapConforming(blob) {
			replacement = append(replacement, cloneLargeBlob(blob))
			continue
		}
		if blobMatchesAnyKey(blob, keys) {
			matchedCount++
			replacement = append(replacement, cloneLargeBlob(blob))
			continue
		}
		unmatchedCount++
	}
	zeroKeys(keys)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return garbageCollectState{}, err
	}
	if err := checkSerializedArrayLimit(support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return garbageCollectState{}, err
	}

	return garbageCollectState{
		support:        support,
		blobs:          cloneLargeBlobs(blobs),
		replacement:    replacement,
		matchedCount:   matchedCount,
		unmatchedCount: unmatchedCount,
		sizeBefore:     sizeBefore,
		sizeAfter:      sizeAfter,
	}, nil
}

func (r Runner) buildGarbageCollectPreview(state garbageCollectState) applargeblobs.MutationPreview {
	return applargeblobs.MutationPreview{
		Operation:                          applargeblobs.MutationGC,
		Device:                             r.env.Selected,
		Support:                            state.support,
		SerializedLargeBlobArraySizeBefore: state.sizeBefore,
		SerializedLargeBlobArraySizeAfter:  state.sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     len(state.replacement),
		MatchedBlobCount:                   state.matchedCount,
		UnmatchedBlobCount:                 state.unmatchedCount,
		Noop:                               state.unmatchedCount == 0,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityDestructive,
				Code:     "large_blob.garbage_collect_unmatched",
				Message:  "Unmatched large-blob entries will be removed from the shared array.",
			},
		},
	}
}

func (r Runner) buildGarbageCollectResult(state garbageCollectState) applargeblobs.MutationResult {
	return applargeblobs.MutationResult{
		Operation:                          applargeblobs.MutationGC,
		DeviceFingerprint:                  r.env.Selected.Fingerprint,
		SerializedLargeBlobArraySizeBefore: state.sizeBefore,
		SerializedLargeBlobArraySizeAfter:  state.sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     len(state.replacement),
		MatchedBlobCount:                   state.matchedCount,
		UnmatchedBlobCount:                 state.unmatchedCount,
		DeletedBlobCount:                   state.unmatchedCount,
		Noop:                               state.unmatchedCount == 0,
	}
}

func largeBlobKeys(inventory appcredentials.InventoryReport) [][]byte {
	keys := make([][]byte, 0, int(inventory.Summary.TotalCredentials))
	for _, group := range inventory.Groups {
		for _, record := range group.Credentials {
			if len(record.LargeBlobKey) == 32 {
				keys = append(keys, slices.Clone(record.LargeBlobKey))
			}
		}
	}

	return keys
}

func blobMatchesAnyKey(blob protocol.LargeBlob, keys [][]byte) bool {
	if !largeBlobMapConforming(blob) {
		return false
	}

	for _, key := range keys {
		raw, err := crypto.DecryptLargeBlob(key, blob)
		if err == nil {
			secret.Zero(raw)

			return true
		}
	}

	return false
}

func largeBlobMapConforming(blob protocol.LargeBlob) bool {
	return len(blob.Nonce) == 12 && blob.Ciphertext != nil
}

func zeroKeys(keys [][]byte) {
	for _, key := range keys {
		secret.Zero(key)
	}
}

func cloneLargeBlob(blob protocol.LargeBlob) protocol.LargeBlob {
	return protocol.LargeBlob{
		Ciphertext: slices.Clone(blob.Ciphertext),
		Nonce:      slices.Clone(blob.Nonce),
		OrigSize:   blob.OrigSize,
	}
}
