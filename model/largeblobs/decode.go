package largeblobs

import "github.com/go-ctap/kit/model/failure"

type DecodeMode string

const (
	DecodeModeNone DecodeMode = "none"
	DecodeModeUTF8 DecodeMode = "utf8"
	DecodeModeJSON DecodeMode = "json"
	DecodeModeCBOR DecodeMode = "cbor"
)

type DecodeStatus struct {
	Requested    bool             `json:"requested"`
	Mode         DecodeMode       `json:"mode"`
	Label        string           `json:"label,omitempty"`
	Success      bool             `json:"success"`
	DecodedText  string           `json:"decodedText,omitempty"`
	DecodedValue any              `json:"decodedValue,omitempty"`
	Failure      *failure.Failure `json:"failure,omitempty"`
}
