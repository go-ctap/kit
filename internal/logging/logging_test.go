package logging

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPayloadUsesStableIndentedJSON(t *testing.T) {
	payload := Payload(SafeValue(struct {
		Command string         `json:"command"`
		Params  map[string]any `json:"params"`
	}{
		Command: "authenticatorGetInfo",
		Params:  map[string]any{"enabled": true},
	}))
	if payload == nil {
		t.Fatal("Payload returned nil")
	}

	want := "{\n  \"command\": \"authenticatorGetInfo\",\n  \"params\": {\n    \"enabled\": true\n  }\n}"
	if payload.JSON != want {
		t.Fatalf("payload JSON = %q, want %q", payload.JSON, want)
	}
	if payload.OriginalBytes != len(want) || payload.StoredBytes != len(want) || payload.Truncated {
		t.Fatalf("payload metadata = %#v", payload)
	}
}

func TestPayloadTruncationIsValidAndBounded(t *testing.T) {
	payload := Payload(SafeValue(map[string]string{"value": strings.Repeat("safe-payload-", 10_000)}))
	if payload == nil {
		t.Fatal("Payload returned nil")
	}
	if !payload.Truncated {
		t.Fatal("payload was not truncated")
	}
	if payload.OriginalBytes <= MaxPayloadBytes {
		t.Fatalf("original bytes = %d, want greater than %d", payload.OriginalBytes, MaxPayloadBytes)
	}
	if payload.StoredBytes > MaxPayloadBytes || payload.StoredBytes != len(payload.JSON) {
		t.Fatalf("stored bytes = %d, JSON bytes = %d", payload.StoredBytes, len(payload.JSON))
	}

	var stored struct {
		Truncated     bool   `json:"truncated"`
		OriginalBytes int    `json:"originalBytes"`
		Preview       string `json:"preview"`
	}
	if err := json.Unmarshal([]byte(payload.JSON), &stored); err != nil {
		t.Fatalf("truncated JSON is invalid: %v", err)
	}
	if !stored.Truncated || stored.OriginalBytes != payload.OriginalBytes || stored.Preview == "" {
		t.Fatalf("truncated JSON = %#v", stored)
	}
}
