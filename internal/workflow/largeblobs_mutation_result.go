package workflow

import (
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
)

func buildMutationResult(
	state targetBlobState,
	operation applargeblobs.MutationOperation,
	proposedByteCount int,
	sizeAfter int,
	noBlob bool,
) applargeblobs.MutationResult {
	return applargeblobs.MutationResult{
		Operation:                          operation,
		DeviceID:                           state.selected.DeviceID,
		CredentialIDHex:                    state.target.Record.CredentialIDHex,
		RPID:                               state.target.RP.ID,
		RPName:                             state.target.RP.Name,
		UserIDHex:                          state.target.User.UserIDHex,
		UserName:                           state.target.User.Name,
		DisplayName:                        state.target.User.DisplayName,
		CurrentByteCount:                   len(state.currentBytes),
		ProposedByteCount:                  proposedByteCount,
		SerializedLargeBlobArraySizeBefore: state.serializedArraySizeBefore,
		SerializedLargeBlobArraySizeAfter:  sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     blobCountAfter(len(state.blobs), operation, noBlob),
		NoBlob:                             noBlob,
	}
}

func buildBlobTarget(target appcredentials.CredentialTarget) applargeblobs.BlobTarget {
	return applargeblobs.BlobTarget{
		CredentialIDHex: target.Record.CredentialIDHex,
		RP:              target.RP,
		User:            target.User,
	}
}

func blobCountAfter(before int, operation applargeblobs.MutationOperation, noBlob bool) int {
	if noBlob {
		return before
	}

	switch operation {
	case applargeblobs.MutationCreate:
		return before + 1
	case applargeblobs.MutationDelete:
		if before == 0 {
			return 0
		}

		return before - 1
	default:
		return before
	}
}
