package ctapkit

import (
	rtlargeblobs "github.com/go-ctap/kit/internal/largeblobs"
	"github.com/go-ctap/kit/model/largeblobs"
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
