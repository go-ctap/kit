package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPINOperationsDoNotMarshalSecrets(t *testing.T) {
	setPIN := SetPINOperation{NewPIN: "123456", DryRun: true}
	raw, err := json.Marshal(setPIN)
	if err != nil {
		t.Fatalf("marshal set PIN: %v", err)
	}

	if strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "newPIN") {
		t.Fatalf("set PIN operation marshaled secret: %s", raw)
	}

	if string(raw) != `{"dryRun":true}` {
		t.Fatalf("marshaled set PIN operation = %s", raw)
	}

	changePIN := ChangePINOperation{CurrentPIN: "123456", NewPIN: "654321", DryRun: true}
	raw, err = json.Marshal(changePIN)
	if err != nil {
		t.Fatalf("marshal change PIN: %v", err)
	}

	if strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "654321") ||
		strings.Contains(string(raw), "currentPIN") || strings.Contains(string(raw), "newPIN") {
		t.Fatalf("change PIN operation marshaled secret: %s", raw)
	}

	if string(raw) != `{"dryRun":true}` {
		t.Fatalf("marshaled change PIN operation = %s", raw)
	}
}
