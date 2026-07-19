package operation

import "testing"

func TestParseCanonicalKinds(t *testing.T) {
	kinds := []Kind{
		Inspect,
		ListCredentials,
		CredentialStoreState,
		DeleteCredential,
		UpdateCredentialUser,
		ReadLargeBlob,
		ListLargeBlobs,
		WriteLargeBlob,
		DeleteLargeBlob,
		GarbageCollectLargeBlobs,
		ConfigStatus,
		BioSensorInfo,
		BioList,
		BioEnroll,
		BioRename,
		BioRemove,
		ResetFactory,
		SetPIN,
		ChangePIN,
		SetAlwaysUV,
		SetMinPINLength,
		EnableLongTouchForReset,
		MakeCredential,
		GetAssertion,
	}

	for _, kind := range kinds {
		parsed, ok := Parse(string(kind))
		if !ok || parsed != kind {
			t.Fatalf("Parse(%q) = %q, %v", kind, parsed, ok)
		}
	}
}

func TestParseRejectsUnknownKind(t *testing.T) {
	if kind, ok := Parse("service.operation"); ok || kind != "" {
		t.Fatalf("Parse(service.operation) = %q, %v", kind, ok)
	}
}
