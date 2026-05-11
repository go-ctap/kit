package workflow

import (
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/kit/model"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/samber/lo"
)

func buildLargeBlobSupportReport(info ctaptypes.AuthenticatorGetInfoResponse) applargeblobs.SupportReport {
	report := applargeblobs.SupportReport{}
	report.LargeBlobs = info.Options[ctaptypes.OptionLargeBlobs]

	report.MaxSerializedLargeBlobArray = snapshotPtr(info.MaxSerializedLargeBlobArray)
	report.LargeBlobKeyExtension = lo.Contains(info.Extensions, webauthntypes.ExtensionIdentifierLargeBlobKey)

	return report
}

func serializedLargeBlobArraySize(blobs []ctaptypes.LargeBlob) (int, error) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return 0, err
	}

	data, err := encMode.Marshal(blobs)
	if err != nil {
		return 0, err
	}

	return len(data) + 16, nil
}

func checkSerializedArrayLimit(limit *uint, size int) error {
	if limit == nil || *limit == 0 || uint(size) <= *limit {
		return nil
	}

	cause := fmt.Errorf(
		"%w: serialized large-blob array would be %d bytes, limit is %d",
		applargeblobs.ErrLargeBlobArrayTooBig,
		size,
		*limit,
	)
	return model.NewRuntimeError(model.ErrorInvalidState, "large blob array capacity would be exceeded", cause)
}

func (r Runner) readLargeBlobArray() ([]ctaptypes.LargeBlob, error) {
	blobs, err := r.largeBlobManager().GetLargeBlobs()
	if err != nil {
		return nil, err
	}

	return cloneLargeBlobs(blobs), nil
}

func cloneLargeBlobs(blobs []ctaptypes.LargeBlob) []ctaptypes.LargeBlob {
	if len(blobs) == 0 {
		return nil
	}

	cloned := make([]ctaptypes.LargeBlob, 0, len(blobs))
	for _, blob := range blobs {
		cloned = append(cloned, ctaptypes.LargeBlob{
			Ciphertext: slices.Clone(blob.Ciphertext),
			Nonce:      slices.Clone(blob.Nonce),
			OrigSize:   blob.OrigSize,
		})
	}

	return cloned
}

func replaceBlob(
	blobs []ctaptypes.LargeBlob,
	index int,
	blob ctaptypes.LargeBlob,
	operation applargeblobs.MutationOperation,
) []ctaptypes.LargeBlob {
	out := cloneLargeBlobs(blobs)
	if operation == applargeblobs.MutationReplace && index >= 0 {
		out[index] = blob

		return out
	}

	return append(out, blob)
}

func removeBlobAt(blobs []ctaptypes.LargeBlob, index int) []ctaptypes.LargeBlob {
	if index < 0 || index >= len(blobs) {
		return cloneLargeBlobs(blobs)
	}

	out := make([]ctaptypes.LargeBlob, 0, len(blobs)-1)
	for candidateIndex, blob := range blobs {
		if candidateIndex == index {
			continue
		}

		out = append(out, ctaptypes.LargeBlob{
			Ciphertext: slices.Clone(blob.Ciphertext),
			Nonce:      slices.Clone(blob.Nonce),
			OrigSize:   blob.OrigSize,
		})
	}

	return out
}

func snapshotPtr[T any](value *T) *T {
	if value == nil {
		return nil
	}

	return new(*value)
}
