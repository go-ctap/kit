package workflow

import (
	"context"
	"slices"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/samber/lo"
)

func buildLargeBlobSupportReport(info protocol.AuthenticatorGetInfoResponse) applargeblobs.SupportReport {
	report := applargeblobs.SupportReport{}
	report.LargeBlobs = info.Options[protocol.OptionLargeBlobs]

	report.MaxSerializedLargeBlobArray = snapshotPtr(info.MaxSerializedLargeBlobArray)
	report.LargeBlobKeyExtension = lo.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)

	return report
}

func serializedLargeBlobArraySize(blobs []protocol.LargeBlob) (int, error) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return 0, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDecode))
	}

	data, err := encMode.Marshal(blobs)
	if err != nil {
		return 0, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDecode))
	}

	return len(data) + 16, nil
}

func checkSerializedArrayLimit(limit *uint, size int) error {
	if limit == nil || uint(size) <= *limit {
		return nil
	}

	return failure.New(failure.CodeLargeBlobArrayTooLarge,
		failure.WithPhase(failure.PhaseValidation),
		failure.WithParams(map[string]string{
			"requested": strconv.FormatUint(uint64(size), 10),
			"limit":     strconv.FormatUint(uint64(*limit), 10),
		}),
	)
}

func (r Runner) readLargeBlobArray(ctx context.Context) ([]protocol.LargeBlob, error) {
	blobs, err := r.largeBlobManager().GetLargeBlobs(ctx)
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	return cloneLargeBlobs(blobs), nil
}

func cloneLargeBlobs(blobs []protocol.LargeBlob) []protocol.LargeBlob {
	if len(blobs) == 0 {
		return nil
	}

	cloned := make([]protocol.LargeBlob, 0, len(blobs))
	for _, blob := range blobs {
		cloned = append(cloned, protocol.LargeBlob{
			Ciphertext: slices.Clone(blob.Ciphertext),
			Nonce:      slices.Clone(blob.Nonce),
			OrigSize:   blob.OrigSize,
		})
	}

	return cloned
}

func replaceBlob(
	blobs []protocol.LargeBlob,
	index int,
	blob protocol.LargeBlob,
	operation applargeblobs.MutationOperation,
) []protocol.LargeBlob {
	out := cloneLargeBlobs(blobs)
	if operation == applargeblobs.MutationReplace && index >= 0 {
		out[index] = blob

		return out
	}

	return append(out, blob)
}

func removeBlobAt(blobs []protocol.LargeBlob, index int) []protocol.LargeBlob {
	if index < 0 || index >= len(blobs) {
		return cloneLargeBlobs(blobs)
	}

	out := make([]protocol.LargeBlob, 0, len(blobs)-1)
	for candidateIndex, blob := range blobs {
		if candidateIndex == index {
			continue
		}

		out = append(out, protocol.LargeBlob{
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
