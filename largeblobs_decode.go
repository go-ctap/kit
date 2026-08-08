package ctapkit

import (
	rtlargeblobs "github.com/telesma-app/kit/internal/largeblobs"
	"github.com/telesma-app/kit/model/largeblobs"
)

// DecodeLargeBlob interprets opaque large-blob bytes without accessing an
// authenticator. It returns a zero result whenever decoding fails.
func DecodeLargeBlob(
	raw []byte,
	mode largeblobs.DecodeMode,
) (largeblobs.DecodeResult, error) {
	result, err := rtlargeblobs.Decode(raw, mode)
	if err != nil {
		return largeblobs.DecodeResult{}, err
	}

	return result, nil
}
