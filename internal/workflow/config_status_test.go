package workflow

import (
	"testing"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	appconfig "github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/failure"
)

func TestRetryStatePreservesClientPINFailure(t *testing.T) {
	raw := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorClientPIN,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}
	state := retryState(
		0,
		nil,
		raw,
		protocol.ClientPINSubCommandGetPINRetries,
	)

	if state.State != appconfig.StateUnknown {
		t.Fatalf("state = %q, want unknown", state.State)
	}
	if state.Failure == nil {
		t.Fatal("failure = nil")
	}
	if state.Failure.Code != failure.CodePINInvalid {
		t.Fatalf("failure code = %s, want %s", state.Failure.Code, failure.CodePINInvalid)
	}
	if state.Failure.Phase != failure.PhaseAuthenticatorCommand {
		t.Fatalf("failure phase = %q", state.Failure.Phase)
	}
	if state.Failure.CTAP == nil {
		t.Fatal("CTAP detail = nil")
	}
	detail := state.Failure.CTAP
	if detail.Command != "authenticatorClientPIN" ||
		detail.CommandCode != uint8(protocol.AuthenticatorClientPIN) ||
		detail.Status != "CTAP2_ERR_PIN_INVALID" ||
		detail.StatusCode != uint8(ctaptransport.CTAP2_ERR_PIN_INVALID) {
		t.Fatalf("CTAP detail = %#v", detail)
	}
	if detail.SubCommandFamily != "clientPIN" ||
		detail.SubCommand != "getPINRetries" ||
		detail.SubCommandCode == nil ||
		*detail.SubCommandCode != uint64(protocol.ClientPINSubCommandGetPINRetries) {
		t.Fatalf("CTAP subcommand detail = %#v", detail)
	}
}
