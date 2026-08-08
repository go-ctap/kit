package ctap23

import (
	"context"
	"fmt"

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

// RunMode selects the non-destructive or complete Authr-Generic-1 test set.
type RunMode string

const (
	// RunModeSafe is the zero-value mode and runs P-1 through P-3 without
	// resetting the authenticator.
	RunModeSafe RunMode = ""
	// RunModeFull runs P-1 through P-5. P-4 and P-5 may each factory-reset
	// the authenticator when their encrypted GetInfo member is advertised.
	RunModeFull RunMode = "full"
)

// Valid reports whether mode is a supported CTAP 2.3 conformance run mode.
func (mode RunMode) Valid() bool {
	return mode == RunModeSafe || mode == RunModeFull
}

// String returns the external name of mode.
func (mode RunMode) String() string {
	if mode == RunModeSafe {
		return "safe"
	}

	return string(mode)
}

// RunRequest selects a CTAP 2.3 test set and supplies its metadata statement.
type RunRequest struct {
	Mode     RunMode  `json:"mode,omitempty"`
	Metadata Metadata `json:"metadata"`
}

// Metadata is the expected authenticator declaration used by metadata-bound
// conformance checks. GetInfoFields records exact CBOR field presence so false
// and zero values remain distinguishable from absent fields.
type Metadata struct {
	GetInfo                 protocol.AuthenticatorGetInfoResponse `json:"getInfo"`
	GetInfoFields           []uint64                              `json:"getInfoFields"`
	UserVerificationMethods protocol.UserVerify                   `json:"userVerificationMethods"`
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

// AuthenticatorResetter performs the reset required by P-4 and P-5. The
// callback allows an owning runtime to route reset through its state and cache
// lifecycle. A nil callback uses the test context's low-level CTAP client.
type AuthenticatorResetter func(context.Context, *client.Client) error

// Config supplies authenticator metadata and execution prerequisites for the
// CTAP 2.3 suite.
type Config struct {
	Metadata                Metadata
	PersistentTokenProvider PinUvAuthTokenProvider
	Resetter                AuthenticatorResetter
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
			encryptedIdentifierTest(config.PersistentTokenProvider, config.Resetter),
			encryptedCredentialStoreStateTest(config.PersistentTokenProvider, config.Resetter),
		},
	}
}

// SuiteFor returns the tests selected by mode.
func SuiteFor(mode RunMode, config Config) (conformance.Suite, error) {
	if !mode.Valid() {
		return conformance.Suite{}, fmt.Errorf("ctap23: unsupported run mode %q", mode)
	}

	suite := Suite(config)
	if mode == RunModeSafe {
		suite.Description = "Non-destructive CTAP 2.3 authenticator conformance tests"
		suite.Tests = suite.Tests[:3]
	}

	return suite, nil
}
