// These tests exercise the public assessment API as an external consumer.
package conformance_test

import (
	"testing"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/conformance"
)

func TestAssessGetInfoAllowsDeclaredMaxMessageSize(t *testing.T) {
	for _, value := range []uint{0, 512, 1024, 4096} {
		info := validFIDO23Info()
		info.MaxMsgSize = value
		assertNoAssessments(t, conformance.AssessGetInfo(info))
	}
}

func TestAssessGetInfoValidatesOptionalListShape(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.AuthenticatorGetInfoResponse)
		rule   conformance.RuleID
	}{
		{"empty PIN protocols", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{}
		}, conformance.RulePinUVAuthProtocolsNonEmpty},
		{"duplicate PIN protocols", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{2, 2}
		}, conformance.RulePinUVAuthProtocolsUnique},
		{"empty transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Transports = []credential.AuthenticatorTransport{}
		}, conformance.RuleTransportsNonEmpty},
		{"duplicate transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Transports = []credential.AuthenticatorTransport{"usb", "usb"}
		}, conformance.RuleTransportsUnique},
		{"empty algorithms", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Algorithms = []credential.PublicKeyCredentialParameters{}
		}, conformance.RuleAlgorithmsNonEmpty},
		{"canonical duplicate algorithms", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.Algorithms = []credential.PublicKeyCredentialParameters{
				{Algorithm: -7},
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -7},
			}
		}, conformance.RuleAlgorithmsUnique},
		{"empty reset transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.TransportsForReset = []credential.AuthenticatorTransport{}
		}, conformance.RuleTransportsForResetNonEmpty},
		{"duplicate reset transports", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.TransportsForReset = []credential.AuthenticatorTransport{"usb", "usb"}
		}, conformance.RuleTransportsForResetUnique},
		{"empty attestation formats", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.AttestationFormats = []attestation.AttestationStatementFormatIdentifier{}
		}, conformance.RuleAttestationFormatsNonEmpty},
		{"duplicate attestation formats", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.AttestationFormats = []attestation.AttestationStatementFormatIdentifier{"packed", "packed"}
		}, conformance.RuleAttestationFormatsUnique},
		{"none attestation format", func(info *protocol.AuthenticatorGetInfoResponse) {
			info.AttestationFormats = []attestation.AttestationStatementFormatIdentifier{"none"}
		}, conformance.RuleAttestationFormatsNoneOmitted},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := validFIDO23Info()
			test.mutate(&info)
			requireOnlyFinding(t, conformance.AssessGetInfo(info), test.rule)
		})
	}
}
