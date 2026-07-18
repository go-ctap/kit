package model

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/kit/model/failure"
)

func TestPINOperationsDecodeSecretsButDoNotMarshalThem(t *testing.T) {
	var setPIN SetPINOperation
	if err := json.Unmarshal([]byte(`{"newPIN":"123456","confirmed":true}`), &setPIN); err != nil {
		t.Fatalf("unmarshal set PIN: %v", err)
	}

	if setPIN.NewPIN != "123456" || !setPIN.Confirmed {
		t.Fatalf("unexpected set PIN operation: %#v", setPIN)
	}

	raw, err := json.Marshal(setPIN)
	if err != nil {
		t.Fatalf("marshal set PIN: %v", err)
	}

	if strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "newPIN") {
		t.Fatalf("set PIN operation marshaled secret: %s", raw)
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

	if strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "654321") ||
		strings.Contains(string(raw), "currentPIN") || strings.Contains(string(raw), "newPIN") {
		t.Fatalf("change PIN operation marshaled secret: %s", raw)
	}
}

func TestPINOperationsWrapInvalidJSONWithoutExposingInput(t *testing.T) {
	const malformed = `{"newPIN":"super-secret","confirmed":"invalid"}`

	for _, target := range []any{new(SetPINOperation), new(ChangePINOperation)} {
		err := json.Unmarshal([]byte(malformed), target)
		if !failure.IsCode(err, failure.CodeRequestJSONInvalid) {
			t.Fatalf("Unmarshal(%T) error = %v, want %s", target, err, failure.CodeRequestJSONInvalid)
		}

		if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
			t.Fatalf("Unmarshal(%T) phase = %q, want %q", target, got, failure.PhaseValidation)
		}

		if strings.Contains(err.Error(), "super-secret") {
			t.Fatalf("Unmarshal(%T) error exposed PIN input: %v", target, err)
		}
	}
}
