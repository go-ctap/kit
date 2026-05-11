package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPINRequestsDecodeSecretsButDoNotMarshalThem(t *testing.T) {
	var setPIN PINSetRequest
	if err := json.Unmarshal([]byte(`{"sessionId":"session-1","newPIN":"123456","confirmed":true}`), &setPIN); err != nil {
		t.Fatalf("unmarshal set PIN request: %v", err)
	}
	if setPIN.SessionID != "session-1" || setPIN.NewPIN != "123456" || !setPIN.Confirmed {
		t.Fatalf("unexpected set PIN request: %#v", setPIN)
	}

	raw, err := json.Marshal(setPIN)
	if err != nil {
		t.Fatalf("marshal set PIN request: %v", err)
	}
	if strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "newPIN") {
		t.Fatalf("set PIN request marshaled secret: %s", raw)
	}

	var changePIN PINChangeRequest
	if err := json.Unmarshal([]byte(`{"sessionId":"session-1","currentPIN":"123456","newPIN":"654321","dryRun":true}`), &changePIN); err != nil {
		t.Fatalf("unmarshal change PIN request: %v", err)
	}
	if changePIN.SessionID != "session-1" || changePIN.CurrentPIN != "123456" || changePIN.NewPIN != "654321" || !changePIN.DryRun {
		t.Fatalf("unexpected change PIN request: %#v", changePIN)
	}

	raw, err = json.Marshal(changePIN)
	if err != nil {
		t.Fatalf("marshal change PIN request: %v", err)
	}
	if strings.Contains(string(raw), "123456") || strings.Contains(string(raw), "654321") ||
		strings.Contains(string(raw), "currentPIN") || strings.Contains(string(raw), "newPIN") {
		t.Fatalf("change PIN request marshaled secret: %s", raw)
	}
}
