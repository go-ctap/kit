// Package largeblobs owns runtime processing of large-blob DTOs.
package largeblobs

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/kit/model/failure"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/samber/lo"
)

func Decode(raw []byte, blobPresent bool, mode applargeblobs.DecodeMode) applargeblobs.DecodeStatus {
	if mode == "" {
		mode = applargeblobs.DecodeModeNone
	}

	status := applargeblobs.DecodeStatus{
		Requested: mode != applargeblobs.DecodeModeNone,
		Mode:      mode,
	}

	if !status.Requested {
		return status
	}

	status.Label = "user-requested interpretation of opaque RP-defined bytes"
	if !blobPresent {
		status.Failure = decodeFailure(failure.CodeLargeBlobMissing)

		return status
	}

	switch mode {
	case applargeblobs.DecodeModeUTF8:
		if !utf8.Valid(raw) {
			status.Failure = decodeFailure(failure.CodeLargeBlobUTF8Invalid)

			return status
		}

		status.Success = true
		status.DecodedText = string(raw)

		return status
	case applargeblobs.DecodeModeJSON:
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			status.Failure = decodeFailure(failure.CodeLargeBlobJSONInvalid)

			return status
		}

		status.Success = true
		status.DecodedValue = value

		return status
	case applargeblobs.DecodeModeCBOR:
		var value any
		if err := cbor.Unmarshal(raw, &value); err != nil {
			status.Failure = decodeFailure(failure.CodeLargeBlobCBORInvalid)

			return status
		}

		status.Success = true
		status.DecodedValue = jsonFriendlyDecodedValue(value)

		return status
	default:
		status.Failure = decodeFailure(failure.CodeLargeBlobDecodeModeUnsupported)

		return status
	}
}

func decodeFailure(code failure.Code) *failure.Failure {
	err := failure.New(code, failure.WithPhase(failure.PhaseDecode))
	snapshot := err.Failure

	return &snapshot
}

func jsonFriendlyDecodedValue(value any) any {
	switch typed := value.(type) {
	case map[any]any:
		return lo.MapEntries(typed, func(key any, value any) (string, any) {
			return fmt.Sprint(key), jsonFriendlyDecodedValue(value)
		})
	case []any:
		return lo.Map(typed, func(value any, _ int) any {
			return jsonFriendlyDecodedValue(value)
		})
	default:
		return typed
	}
}
