package ctap23

import (
	"context"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/upstream"
)

const (
	SuiteIDAuthenticator  conformance.SuiteID = "fido.ctap2.3.authenticator"
	TestIDAuthrGeneric1P1 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-1"
	TestIDAuthrGeneric1P2 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-2"
	TestIDAuthrGeneric1P3 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-3"
	TestIDAuthrGeneric1P4 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-4"
	TestIDAuthrGeneric1P5 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-5"
)

// Metadata is the expected authenticator declaration used by metadata-bound
// conformance checks. GetInfoFields records exact CBOR field presence so false
// and zero values remain distinguishable from absent fields.
type Metadata struct {
	GetInfo                 protocol.AuthenticatorGetInfoResponse
	GetInfoFields           []uint64
	UserVerificationMethods protocol.UserVerify
}

// PinUvAuthTokenProvider obtains a pinUvAuthToken with the requested
// permission. Ownership of the returned buffer transfers to the suite, which
// wipes it after the current test. The provider may use PIN or built-in UV and
// may configure verification when the authenticator was previously reset.
type PinUvAuthTokenProvider func(
	ctx context.Context,
	client *client.Client,
	permission protocol.Permission,
) ([]byte, error)

// Config supplies authenticator metadata and execution prerequisites for the
// CTAP 2.3 suite.
type Config struct {
	Metadata                Metadata
	PersistentTokenProvider PinUvAuthTokenProvider
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
			getInfoOptionsTest(config.Metadata),
			getInfoPinUvAuthProtocolsTest(config.Metadata),
			encryptedIdentifierTest(config.PersistentTokenProvider),
			encryptedCredentialStoreStateTest(config.PersistentTokenProvider),
		},
	}
}
