package getinfo

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/inspect"
)

func TestResolveOptionPresenceAndDefaults(t *testing.T) {
	absent := Resolve(protocol.AuthenticatorGetInfoResponse{})
	for _, id := range []model.FactID{
		model.FactIDUserPresence,
		model.FactIDClientPIN,
		model.FactIDResidentCredentials,
		model.FactIDAlwaysUV,
	} {
		fact := requireFact(t, absent, id)
		if fact.State != model.FactStateUnknown || fact.Origin != model.FactOriginAbsent || fact.Value.Boolean != nil {
			t.Fatalf("absent options fact %s = %#v, want unknown/absent without value", id, fact)
		}
	}

	defaults := Resolve(protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})
	assertBooleanFact(t, defaults, model.FactIDUserPresence, model.FactStateSupported, model.FactOriginSpecDefault, true)
	assertBooleanFact(t, defaults, model.FactIDClientPIN, model.FactStateUnsupported, model.FactOriginSpecDefault, false)
	assertBooleanFact(t, defaults, model.FactIDResidentCredentials, model.FactStateUnsupported, model.FactOriginSpecDefault, false)
	assertBooleanFact(t, defaults, model.FactIDClientPINMCGAPermissions, model.FactStateEnabled, model.FactOriginSpecDefault, true)
	assertBooleanFact(t, defaults, model.FactIDMakeCredentialUVRequirement, model.FactStateRequired, model.FactOriginSpecDefault, true)

	explicit := Resolve(protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionUserPresence:                   false,
		protocol.OptionClientPIN:                      false,
		protocol.OptionAlwaysUv:                       false,
		protocol.OptionLargeBlobs:                     false,
		protocol.OptionNoMcGaPermissionsWithClientPin: true,
		protocol.OptionMakeCredentialUvNotRequired:    true,
	}})
	assertBooleanFact(t, explicit, model.FactIDUserPresence, model.FactStateUnsupported, model.FactOriginReported, false)
	assertBooleanFact(t, explicit, model.FactIDClientPIN, model.FactStateNotConfigured, model.FactOriginReported, false)
	assertBooleanFact(t, explicit, model.FactIDAlwaysUV, model.FactStateDisabled, model.FactOriginReported, false)
	assertBooleanFact(t, explicit, model.FactIDLargeBlobs, model.FactStateUnsupported, model.FactOriginReported, false)
	assertBooleanFact(t, explicit, model.FactIDClientPINMCGAPermissions, model.FactStateDisabled, model.FactOriginDerived, false)
	assertBooleanFact(t, explicit, model.FactIDMakeCredentialUVRequirement, model.FactStateNotRequired, model.FactOriginDerived, false)
}

func TestResolveEffectiveLimits(t *testing.T) {
	defaults := Resolve(protocol.AuthenticatorGetInfoResponse{})
	assertIntegerFact(t, defaults, model.FactIDEffectiveMaxMessageSize, 1024, model.FactOriginSpecDefault, model.FactUnitBytes)
	assertIntegerFact(t, defaults, model.FactIDEffectiveMinPINLength, 4, model.FactOriginSpecDefault, model.FactUnitCodePoints)
	assertIntegerFact(t, defaults, model.FactIDEffectiveMaxPINLength, 63, model.FactOriginSpecDefault, model.FactUnitCodePoints)

	reported := Resolve(protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize:   2048,
		MinPINLength: 8,
		MaxPINLength: 64,
	})
	assertIntegerFact(t, reported, model.FactIDEffectiveMaxMessageSize, 2048, model.FactOriginReported, model.FactUnitBytes)
	assertIntegerFact(t, reported, model.FactIDEffectiveMinPINLength, 8, model.FactOriginReported, model.FactUnitCodePoints)
	assertIntegerFact(t, reported, model.FactIDEffectiveMaxPINLength, 64, model.FactOriginReported, model.FactUnitCodePoints)
}

func TestResolveVersionsAndExtensions(t *testing.T) {
	absent := Resolve(protocol.AuthenticatorGetInfoResponse{})
	if fact := requireFact(t, absent, model.FactIDVersionFIDO23); fact.State != model.FactStateUnknown {
		t.Fatalf("absent version = %#v, want unknown", fact)
	}
	if fact := requireFact(t, absent, model.FactIDExtensionLargeBlobKey); fact.State != model.FactStateUnknown {
		t.Fatalf("absent extension = %#v, want unknown", fact)
	}

	reported := Resolve(protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_1, protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlobKey},
	})
	assertBooleanFact(t, reported, model.FactIDVersionFIDO23, model.FactStateSupported, model.FactOriginDerived, true)
	assertBooleanFact(t, reported, model.FactIDVersionFIDO20, model.FactStateUnsupported, model.FactOriginDerived, false)
	assertBooleanFact(t, reported, model.FactIDLargeBlobKey, model.FactStateSupported, model.FactOriginDerived, true)
	assertBooleanFact(t, reported, model.FactIDExtensionLargeBlob, model.FactStateUnsupported, model.FactOriginDerived, false)
}

func TestResolveListsAndJSONAreDeterministic(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{},
		Algorithms: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		AuthenticatorConfigCommands:   []protocol.ConfigSubCommand{4, 1},
		VendorPrototypeConfigCommands: []protocol.VendorCommandID{0x1_0000_0000, 7},
		Certifications:                map[string]uint64{"FIPS-CMVP-2": 3, "FIDO": 2},
	}

	first := Resolve(info)
	second := Resolve(info)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Resolve is not deterministic:\nfirst: %#v\nsecond: %#v", first, second)
	}

	commands := requireFact(t, first, model.FactIDAuthenticatorConfigCommands)
	if commands.Value.List == nil || !reflect.DeepEqual(*commands.Value.List, []string{"4", "1"}) {
		t.Fatalf("config commands = %#v", commands.Value)
	}
	vendorCommands := requireFact(t, first, model.FactIDVendorPrototypeConfigCommands)
	if vendorCommands.Value.List == nil || !reflect.DeepEqual(*vendorCommands.Value.List, []string{"4294967296", "7"}) {
		t.Fatalf("vendor commands = %#v", vendorCommands.Value)
	}
	certifications := requireFact(t, first, model.FactIDCertifications)
	if certifications.Value.List == nil || !reflect.DeepEqual(*certifications.Value.List, []string{"FIDO=2", "FIPS-CMVP-2=3"}) {
		t.Fatalf("certifications = %#v", certifications.Value)
	}
	algorithms := requireFact(t, first, model.FactIDAlgorithms)
	if algorithms.Value.List == nil || !reflect.DeepEqual(*algorithms.Value.List, []string{"public-key:-7"}) {
		t.Fatalf("algorithms = %#v", algorithms.Value)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("Marshal first assessment: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("Marshal second assessment: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("JSON differs:\n%s\n%s", firstJSON, secondJSON)
	}

	emptyAttestation := requireFact(t, first, model.FactIDAttestationFormats)
	if emptyAttestation.Value.List == nil || len(*emptyAttestation.Value.List) != 0 {
		t.Fatalf("default attestation list = %#v, want present empty list", emptyAttestation.Value)
	}
}

func TestResolveReturnsStableUniqueFactInventory(t *testing.T) {
	first := Resolve(protocol.AuthenticatorGetInfoResponse{})
	second := Resolve(protocol.AuthenticatorGetInfoResponse{})
	if len(first.Facts) == 0 {
		t.Fatal("facts must be non-empty")
	}
	if !reflect.DeepEqual(first.Facts, second.Facts) {
		t.Fatal("fact order is not deterministic")
	}

	seen := make(map[model.FactID]struct{}, len(first.Facts))
	for _, fact := range first.Facts {
		if _, duplicate := seen[fact.ID]; duplicate {
			t.Fatalf("duplicate fact ID %q", fact.ID)
		}
		seen[fact.ID] = struct{}{}
		if fact.Source == "" {
			t.Fatalf("fact %q has an empty source", fact.ID)
		}
	}
}

func requireFact(t *testing.T, assessment model.Assessment, id model.FactID) model.Fact {
	t.Helper()

	fact, ok := Find(assessment, id)
	if !ok {
		t.Fatalf("fact %q not found", id)
	}

	return fact
}

func assertBooleanFact(t *testing.T, assessment model.Assessment, id model.FactID, state model.FactState, origin model.FactOrigin, value bool) {
	t.Helper()

	fact := requireFact(t, assessment, id)
	if fact.State != state || fact.Origin != origin || fact.Value.Kind != model.FactValueBoolean || fact.Value.Boolean == nil || *fact.Value.Boolean != value {
		t.Fatalf("fact %q = %#v, want state=%s origin=%s boolean=%t", id, fact, state, origin, value)
	}
}

func assertIntegerFact(t *testing.T, assessment model.Assessment, id model.FactID, value uint64, origin model.FactOrigin, unit model.FactUnit) {
	t.Helper()

	fact := requireFact(t, assessment, id)
	if fact.State != model.FactStateObserved || fact.Origin != origin || fact.Value.Kind != model.FactValueInteger || fact.Value.Integer == nil || *fact.Value.Integer != value || fact.Value.Unit != unit {
		t.Fatalf("fact %q = %#v, want observed/%s integer=%d unit=%s", id, fact, origin, value, unit)
	}
}
