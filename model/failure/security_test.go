package failure

import (
	"encoding/json"
	"errors"
	"strings"
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

	text := string(raw)
	for _, forbidden := range []string{
		"123456",
		"token-secret",
		"erase-everything",
		"pinUvAuthToken",
		"resetPhrase",
		"current PIN",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Marshal leaked %q: %s", forbidden, text)
		}
	}

	if !strings.Contains(text, `"field":"currentPIN"`) {
		t.Fatalf("Marshal omitted allowlisted parameter: %s", text)
	}

	if !strings.Contains(text, `"category":"invalid-operation"`) {
		t.Fatalf("Marshal omitted the registered category: %s", text)
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

	text := string(raw)
	if strings.Contains(text, canary) {
		t.Fatalf("Marshal leaked unregistered metadata: %s", text)
	}

	for _, expected := range []string{
		`"command":"authenticatorClientPIN"`,
		`"subCommandFamily":"clientPIN"`,
		`"subCommand":"getPinUvAuthTokenUsingPinWithPermissions"`,
		`"status":"CTAP2_ERR_PIN_AUTH_INVALID"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Marshal omitted canonical metadata %s: %s", expected, text)
		}
	}
}
