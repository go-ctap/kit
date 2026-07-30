package largeblobs

type DecodeMode string

const (
	DecodeModeUTF8 DecodeMode = "utf8"
	DecodeModeJSON DecodeMode = "json"
	DecodeModeCBOR DecodeMode = "cbor"
)

type DecodeResult struct {
	Mode  DecodeMode `json:"mode"`
	Text  string     `json:"text,omitempty"`
	Value any        `json:"value,omitempty"`
}
