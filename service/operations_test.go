package service

import (
	"encoding/json"
	"testing"
)

func TestPINRequestsRoundTripSecrets(t *testing.T) {
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
	var setPINRoundTrip PINSetRequest
	if err := json.Unmarshal(raw, &setPINRoundTrip); err != nil {
		t.Fatalf("unmarshal marshaled set PIN request: %v", err)
	}
	if setPINRoundTrip != setPIN {
		t.Fatalf("set PIN request round trip = %#v, want %#v", setPINRoundTrip, setPIN)
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
	var changePINRoundTrip PINChangeRequest
	if err := json.Unmarshal(raw, &changePINRoundTrip); err != nil {
		t.Fatalf("unmarshal marshaled change PIN request: %v", err)
	}
	if changePINRoundTrip != changePIN {
		t.Fatalf("change PIN request round trip = %#v, want %#v", changePINRoundTrip, changePIN)
	}
}
