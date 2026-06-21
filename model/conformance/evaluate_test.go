package conformance_test

import (
	"testing"

	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/conformance"
	"github.com/google/uuid"
	"github.com/ldclabs/cose/key"
)

func TestEvaluateGetInfoAcceptsCompleteCTAP23Profile(t *testing.T) {
	findings := conformance.EvaluateGetInfo(validCTAP23Info())
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

func TestEvaluateGetInfoFlagsCTAP23PINUVTokenAndProtocolRequirements(t *testing.T) {
	info := validCTAP23Info()
	info.Options = map[protocol.Option]bool{
		protocol.OptionClientPIN:            true,
		protocol.OptionCredentialManagement: true,
		protocol.OptionPinUvAuthToken:       false,
		protocol.OptionResidentKeys:         true,
	}
	info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne}

	assertFindingIDs(t, conformance.EvaluateGetInfo(info), conformance.FindingCTAP23PinUVAuthToken, conformance.FindingCTAP23PinProtocolTwo)
}

func TestEvaluateGetInfoFlagsMinimumPINLengthCapabilityInconsistencies(t *testing.T) {
	info := validCTAP23Info()
	info.Extensions = []extension.ExtensionIdentifier{
		extension.ExtensionIdentifierHMACSecret,
		extension.ExtensionIdentifierCredentialProtection,
		extension.ExtensionIdentifierMinPinLength,
	}
	info.Options = map[protocol.Option]bool{
		protocol.OptionSetMinPINLength: true,
	}
	info.AuthenticatorConfigCommands = []uint{}
	info.MinPINLength = uintPtr(3)
	info.MaxPINLength = uintPtr(7)
	info.MaxRPIDsForSetMinPINLength = uintPtr(2)

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingSetMinPINWithoutUV,
		conformance.FindingSetMinPINCommandMissing,
		conformance.FindingMinPINLengthInvalid,
		conformance.FindingMinPINWithoutClientPIN,
		conformance.FindingMaxPINLengthInvalid,
		conformance.FindingMaxPINWithoutClientPIN,
	)
}

func TestEvaluateGetInfoFlagsMissingConfigCommandsWhenSubcommandsRequired(t *testing.T) {
	info := validCTAP23Info()
	info.AuthenticatorConfigCommands = nil
	info.Options[protocol.OptionEnterpriseAttestation] = true
	info.VendorPrototypeConfigCommands = []uint{1}
	info.LongTouchForReset = boolPtr(true)

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingSetMinPINCommandMissing,
		conformance.FindingEnterpriseAttestationCommandMissing,
		conformance.FindingVendorPrototypeCommandMissing,
		conformance.FindingLongTouchCommandMissing,
	)
}

func TestEvaluateGetInfoFlagsMalformedOrDuplicateRequiredLists(t *testing.T) {
	info := validCTAP23Info()
	info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo, protocol.PinUvAuthProtocolTwo}
	info.Transports = []string{}
	info.Algorithms = []credential.PublicKeyCredentialParameters{
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: key.Alg(-7)},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: key.Alg(-7)},
	}

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingPinUVAuthProtocolsListDuplicate,
		conformance.FindingTransportsListEmpty,
		conformance.FindingAlgorithmsListDuplicate,
	)
}

func TestEvaluateGetInfoFlagsAdditionalListConstraints(t *testing.T) {
	info := validCTAP23Info()
	info.TransportsForReset = []string{}
	info.AttestationFormats = []string{"packed", "packed", "none"}

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingTransportsForResetListEmpty,
		conformance.FindingAttestationFormatsListDuplicate,
		conformance.FindingAttestationFormatsNone,
	)
}

func TestEvaluateGetInfoFlagsSetMinPINLengthPresenceWithoutUVSupport(t *testing.T) {
	info := validCTAP23Info()
	info.Options = map[protocol.Option]bool{
		protocol.OptionSetMinPINLength: false,
	}

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingSetMinPINWithoutUV,
	)
}

func TestEvaluateGetInfoFlagsSetMinPINLengthFeatureGaps(t *testing.T) {
	info := validCTAP23Info()
	info.Extensions = []extension.ExtensionIdentifier{
		extension.ExtensionIdentifierHMACSecret,
		extension.ExtensionIdentifierCredentialProtection,
	}
	info.MaxRPIDsForSetMinPINLength = nil
	info.Options[protocol.OptionAlwaysUv] = false
	info.Options[protocol.OptionAuthenticatorConfig] = false

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingSetMinPINWithoutExtension,
		conformance.FindingMaxRPIDsMissingWithSetMinPIN,
		conformance.FindingAlwaysUVCommandMissing,
		conformance.FindingConfigCommandsWithoutAuthnrCfg,
	)
}

func TestEvaluateGetInfoFlagsMaxCredBlobLengthWithoutCredBlobExtension(t *testing.T) {
	info := validCTAP23Info()
	info.Extensions = nil
	info.MaxCredBlobLength = uintPtr(32)

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingCredBlobLimitWithoutExtension,
	)
}

func TestEvaluateGetInfoFlagsPinComplexityExtensionWithoutClientPIN(t *testing.T) {
	info := validCTAP23Info()
	delete(info.Options, protocol.OptionClientPIN)
	info.Extensions = append(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy)

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingPinComplexityWithoutClientPIN,
	)
}

func TestEvaluateGetInfoFlagsLargeBlobExtensionConflict(t *testing.T) {
	info := validCTAP23Info()
	info.Extensions = append(info.Extensions,
		extension.ExtensionIdentifierLargeBlob,
		extension.ExtensionIdentifierLargeBlobKey,
	)

	assertFindingIDs(t, conformance.EvaluateGetInfo(info),
		conformance.FindingLargeBlobModeConflict,
		conformance.FindingLargeBlobExtensionsConflict,
	)
}

func validCTAP23Info() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions: []protocol.Version{protocol.FIDO_2_3},
		AAGUID:   uuid.Must(uuid.Parse("00112233-4455-6677-8899-aabbccddeeff")),
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierCredentialProtection,
			extension.ExtensionIdentifierMinPinLength,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionResidentKeys:         true,
			protocol.OptionClientPIN:            true,
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionLargeBlobs:           true,
			protocol.OptionAuthenticatorConfig:  true,
			protocol.OptionSetMinPINLength:      true,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Transports:         []string{"usb"},
		Algorithms: []credential.PublicKeyCredentialParameters{
			{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: key.Alg(-7)},
		},
		AuthenticatorConfigCommands: []uint{3},
		MaxCredentialCountInList:    uintPtr(1),
		MaxCredentialIdLength:       uintPtr(64),
		MaxMsgSize:                  uintPtr(1200),
		PreferredPlatformUvAttempts: uintPtr(1),
		MaxSerializedLargeBlobArray: uintPtr(1024),
		MinPINLength:                uintPtr(4),
		MaxPINLength:                uintPtr(64),
		MaxRPIDsForSetMinPINLength:  uintPtr(3),
	}
}

func assertFindingIDs(t *testing.T, findings []conformance.Finding, ids ...conformance.FindingID) {
	t.Helper()

	seen := make(map[conformance.FindingID]bool, len(findings))
	for _, finding := range findings {
		seen[finding.ID] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatalf("finding IDs = %#v, missing %s", seen, id)
		}
	}
}

func uintPtr(value uint) *uint {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}
