package config

import (
	"encoding/json"
	"testing"
)

func TestPINOperationsDoNotMarshalSecrets(t *testing.T) {
	tests := []struct {
		name      string
		operation any
	}{
		{
			name:      "set PIN",
			operation: SetPINOperation{NewPIN: "123456", DryRun: true},
		},
		{
			name:      "change PIN",
			operation: ChangePINOperation{CurrentPIN: "123456", NewPIN: "654321", DryRun: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.operation)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			if string(raw) != `{"dryRun":true}` {
				t.Fatalf("Marshal = %s, want secret-free dry-run form", raw)
			}
		})
	}
}
