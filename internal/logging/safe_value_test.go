package logging

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSafeValueKeepsDiagnosticsAndRedactsKnownSecrets(t *testing.T) {
	const (
		pin          = "sentinel-pin-101"
		confirmation = "sentinel-confirmation-202"
		public       = "public-diagnostic"
	)
	value := struct {
		Name                string `json:"name"`
		PIN                 string `json:"pin"`
		ConfirmationMessage string `json:"confirmationMessage"`
		Confirmed           bool   `json:"confirmed"`
	}{
		Name:                public,
		PIN:                 pin,
		ConfirmationMessage: confirmation,
		Confirmed:           true,
	}

	safe := SafeValue(value)
	payload := Payload(safe)
	if payload == nil || !strings.Contains(payload.JSON, public) {
		t.Fatalf("safe payload lost public field: %#v", payload)
	}
	for _, secret := range []string{pin, confirmation} {
		if strings.Contains(payload.JSON, secret) || strings.Contains(payload.JSON, base64.StdEncoding.EncodeToString([]byte(secret))) {
			t.Fatalf("safe payload contains %q: %s", secret, payload.JSON)
		}
	}
	if !strings.Contains(payload.JSON, Redacted) {
		t.Fatalf("safe payload has no redaction marker: %s", payload.JSON)
	}
	if strings.Join(safe.RedactedFields, ",") != "pin,confirmationMessage,confirmed" {
		t.Fatalf("redacted fields = %v", safe.RedactedFields)
	}
}

func TestSafeValueRedactsSecretMapKeysBeforeJSON(t *testing.T) {
	const secret = "sentinel-map-secret-303"
	safe := SafeValue(map[string]any{
		"public":      "visible",
		"hmac-secret": []byte(secret),
	})
	raw, err := json.Marshal(safe.Value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("safe map contains secret: %s", raw)
	}
	if len(safe.RedactedFields) != 1 || safe.RedactedFields[0] != "hmac-secret" {
		t.Fatalf("redacted fields = %v", safe.RedactedFields)
	}
}

func TestSafeValuePreservesExplicitPointerZeroValues(t *testing.T) {
	retriesRemaining := uint(0)
	powerCycleState := false
	safe := SafeValue(struct {
		RetriesRemaining *uint `json:"retriesRemaining,omitempty"`
		PowerCycleState  *bool `json:"powerCycleState,omitempty"`
	}{
		RetriesRemaining: &retriesRemaining,
		PowerCycleState:  &powerCycleState,
	})

	payload := Payload(safe)
	if payload == nil || !strings.Contains(payload.JSON, `"retriesRemaining": 0`) ||
		!strings.Contains(payload.JSON, `"powerCycleState": false`) {
		t.Fatalf("safe payload lost explicit pointer zero values: %#v", payload)
	}
}

func TestSafeValueRedactsCTAP23LargeBlobPaymentAndStoreState(t *testing.T) {
	const secret = "sentinel-ctap23-secret"
	safe := SafeValue(map[string]any{
		"largeBlob": map[string]any{
			"write":   []byte(secret),
			"blobHex": secret,
		},
		"payment": map[string]any{
			"instrument": map[string]any{"details": secret},
		},
		"authenticatorIdentifierHex": secret,
		"credentialStoreStateHex":    secret,
	})

	raw, err := json.Marshal(safe.Value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("safe CTAP 2.3 payload contains secret: %s", raw)
	}
	for _, field := range []string{
		"largeBlob.write",
		"largeBlob.blobHex",
		"payment",
		"authenticatorIdentifierHex",
		"credentialStoreStateHex",
	} {
		if !slices.Contains(safe.RedactedFields, field) {
			t.Fatalf("redacted fields = %v, want %s", safe.RedactedFields, field)
		}
	}
}
