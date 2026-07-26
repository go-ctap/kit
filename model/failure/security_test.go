package failure

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestJSONNeverIncludesCauseOrRejectedParams(t *testing.T) {
	err := Wrap(
		CodePINRequired,
		errors.New("current PIN 123456; pinUvAuthToken token-secret; reset phrase erase-everything"),
		WithParams(map[string]string{
			"field":          "currentPIN",
			"currentPIN":     "123456",
			"pinUvAuthToken": "token-secret",
			"resetPhrase":    "erase-everything",
		}),
	)

	raw, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}

	want := `{"code":"PIN_REQUIRED","category":"invalid-operation","params":{"field":"currentPIN"}}`
	if string(raw) != want {
		t.Fatalf("Marshal = %s, want redacted wire form %s", raw, want)
	}
}

func TestConstructionCanonicalizesOperationAndCTAPSymbols(t *testing.T) {
	const canary = "PIN-123456"

	knownSubCommand := uint64(9)
	err := New(
		CodePINUVAuthInvalid,
		WithOperation(canary),
		WithCTAP(&CTAPDetail{
			Command:          canary,
			CommandCode:      0x06,
			SubCommandFamily: canary,
			SubCommand:       canary,
			SubCommandCode:   &knownSubCommand,
			Status:           canary,
			StatusCode:       0x33,
		}),
	)

	raw, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}

	want := `{"code":"PIN_UV_AUTH_INVALID","category":"invalid-state","ctap":{"command":"authenticatorClientPIN","commandCode":6,"subCommandFamily":"clientPIN","subCommand":"getPinUvAuthTokenUsingPinWithPermissions","subCommandCode":9,"status":"CTAP2_ERR_PIN_AUTH_INVALID","statusCode":51}}`
	if string(raw) != want {
		t.Fatalf("Marshal = %s, want canonical wire form %s", raw, want)
	}
}
