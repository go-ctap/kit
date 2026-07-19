package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPINOperationsParticipateInJSONTransport(t *testing.T) {
	var setPIN SetPINOperation
	if err := json.Unmarshal([]byte(`{"newPIN":"123456"}`), &setPIN); err != nil {
		t.Fatalf("unmarshal set PIN: %v", err)
	}

	if setPIN.NewPIN != "123456" {
		t.Fatalf("unexpected set PIN operation: %#v", setPIN)
	}

	raw, err := json.Marshal(setPIN)
	if err != nil {
		t.Fatalf("marshal set PIN: %v", err)
	}

	if !strings.Contains(string(raw), `"newPIN":"123456"`) {
		t.Fatalf("set PIN operation JSON = %s", raw)
	}

	var changePIN ChangePINOperation
	if err := json.Unmarshal([]byte(`{"currentPIN":"123456","newPIN":"654321","dryRun":true}`), &changePIN); err != nil {
		t.Fatalf("unmarshal change PIN: %v", err)
	}

	if changePIN.CurrentPIN != "123456" || changePIN.NewPIN != "654321" || !changePIN.DryRun {
		t.Fatalf("unexpected change PIN operation: %#v", changePIN)
	}

	raw, err = json.Marshal(changePIN)
	if err != nil {
		t.Fatalf("marshal change PIN: %v", err)
	}

	if !strings.Contains(string(raw), `"currentPIN":"123456"`) ||
		!strings.Contains(string(raw), `"newPIN":"654321"`) {
		t.Fatalf("change PIN operation JSON = %s", raw)
	}
}

func TestPINOperationsRejectInvalidJSON(t *testing.T) {
	const malformed = `{"newPIN":false}`

	for _, target := range []any{new(SetPINOperation), new(ChangePINOperation)} {
		err := json.Unmarshal([]byte(malformed), target)
		if err == nil {
			t.Fatalf("Unmarshal(%T) error = nil", target)
		}
	}
}
