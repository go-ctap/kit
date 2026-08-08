package ctap23

import (
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/conformance"
	"github.com/go-ctap/kit/conformance/upstream"
)

const (
	SuiteIDAuthenticator  conformance.SuiteID = "fido.ctap2.3.authenticator"
	TestIDAuthrGeneric1P1 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-1"
)

// Metadata is the expected authenticator declaration used by metadata-bound
// conformance checks. GetInfoFields records exact CBOR field presence so false
// and zero values remain distinguishable from absent fields.
type Metadata struct {
	GetInfo                 protocol.AuthenticatorGetInfoResponse
	GetInfoFields           []uint64
	UserVerificationMethods protocol.UserVerify
}

// Config supplies the authenticator metadata required by the CTAP 2.3 suite.
type Config struct {
	Metadata Metadata
}

// Suite returns the currently implemented CTAP 2.3 authenticator tests.
func Suite(config Config) conformance.Suite {
	source := upstream.Current().Source

	return conformance.Suite{
		ID:          SuiteIDAuthenticator,
		Name:        "CTAP 2.3 authenticator",
		Description: "Executable CTAP 2.3 authenticator conformance tests",
		Source:      source,
		Tests: []conformance.Test{
			getInfoTest(config.Metadata),
		},
	}
}
