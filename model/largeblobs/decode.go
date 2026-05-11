package largeblobs

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/samber/lo"
)

type DecodeMode string

const (
	DecodeModeNone DecodeMode = "none"
	DecodeModeUTF8 DecodeMode = "utf8"
	DecodeModeJSON DecodeMode = "json"
	DecodeModeCBOR DecodeMode = "cbor"
)

type DecodeStatus struct {
	Requested    bool       `json:"requested"`
	Mode         DecodeMode `json:"mode"`
	Label        string     `json:"label,omitempty"`
	Success      bool       `json:"success"`
	DecodedText  string     `json:"decodedText,omitempty"`
	DecodedValue any        `json:"decodedValue,omitempty"`
	Failure      string     `json:"failure,omitempty"`
}

func DecodeLargeBlob(raw []byte, blobPresent bool, mode DecodeMode) DecodeStatus {
	if mode == "" {
		mode = DecodeModeNone
	}

	status := DecodeStatus{
		Requested: mode != DecodeModeNone,
		Mode:      mode,
	}
	if !status.Requested {
		return status
	}

	status.Label = "user-requested interpretation of opaque RP-defined bytes"
	if !blobPresent {
		status.Failure = "no blob present"

		return status
	}

	switch mode {
	case DecodeModeUTF8:
		if !utf8.Valid(raw) {
			status.Failure = "payload is not valid UTF-8"

			return status
		}

		status.Success = true
		status.DecodedText = string(raw)

		return status
	case DecodeModeJSON:
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			status.Failure = "payload is not valid JSON: " + err.Error()

			return status
		}

		status.Success = true
		status.DecodedValue = value

		return status
	case DecodeModeCBOR:
		var value any
		if err := cbor.Unmarshal(raw, &value); err != nil {
			status.Failure = "payload is not valid CBOR: " + err.Error()

			return status
		}

		status.Success = true
		status.DecodedValue = jsonFriendlyDecodedValue(value)

		return status
	default:
		status.Failure = "unsupported decode mode"

		return status
	}
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
