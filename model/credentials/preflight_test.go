package credentials

import (
	"errors"
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

func TestFindCredentialByHexID(t *testing.T) {
	report := sampleInventoryReport()

	target, err := FindCredentialByHexID(report, "deadbeef")
	if err != nil {
		t.Fatalf("FindCredentialByHexID: %v", err)
	}

	if target.RP.ID != "example.com" {
		t.Fatalf("RP.ID = %q, want example.com", target.RP.ID)
	}

	if target.User.UserIDHex != "0102" {
		t.Fatalf("UserIDHex = %q, want 0102", target.User.UserIDHex)
	}
}

func TestBuildDeletePreview(t *testing.T) {
	report := sampleInventoryReport()

	preview, err := BuildDeletePreview(report, "deadbeef")
	if err != nil {
		t.Fatalf("BuildDeletePreview: %v", err)
	}

	if preview.CredentialIDHex != "deadbeef" {
		t.Fatalf("CredentialIDHex = %q, want deadbeef", preview.CredentialIDHex)
	}

	if len(preview.Warnings) != 2 {
		t.Fatalf("Warnings = %#v, want 2 warnings", preview.Warnings)
	}

	if preview.Warnings[0].Severity != safety.SeverityDestructive {
		t.Fatalf("first warning severity = %q, want destructive", preview.Warnings[0].Severity)
	}

	if preview.Warnings[0].Code != "credential.delete.destructive" {
		t.Fatalf("first warning code = %q, want credential.delete.destructive", preview.Warnings[0].Code)
	}

	if preview.Warnings[1].Code != "credential.delete.irreversible" {
		t.Fatalf("second warning code = %q, want credential.delete.irreversible", preview.Warnings[1].Code)
	}
}

func TestBuildDeletePreviewMissingCredential(t *testing.T) {
	if _, err := BuildDeletePreview(sampleInventoryReport(), ""); err == nil {
		t.Fatal("BuildDeletePreview(empty) error = nil, want failure")
	}
}

func TestBuildUpdateUserPreviewRejectsInvalidUserIDHex(t *testing.T) {
	for _, userIDHex := range []string{"zz", "abc"} {
		_, err := BuildUpdateUserPreview(sampleInventoryReport(), UpdateUserRequest{
			CredentialIDHex: "deadbeef",
			UserIDHex:       userIDHex,
			UserIDProvided:  true,
		})
		if !errors.Is(err, ErrInvalidUserIDHex) {
			t.Fatalf("BuildUpdateUserPreview(%q) error = %v, want ErrInvalidUserIDHex", userIDHex, err)
		}
	}
}

func TestBuildUpdateUserPreviewNormalizesUserIDHex(t *testing.T) {
	preview, err := BuildUpdateUserPreview(sampleInventoryReport(), UpdateUserRequest{
		CredentialIDHex: "deadbeef",
		UserIDHex:       "0A0B",
		UserIDProvided:  true,
	})
	if err != nil {
		t.Fatalf("BuildUpdateUserPreview: %v", err)
	}

	if preview.Proposed.UserIDHex != "0a0b" {
		t.Fatalf("Proposed.UserIDHex = %q, want normalized lower-case hex", preview.Proposed.UserIDHex)
	}
}

func TestBuildUpdateUserPreviewEmptyProvidedUserIDFallsBack(t *testing.T) {
	preview, err := BuildUpdateUserPreview(sampleInventoryReport(), UpdateUserRequest{
		CredentialIDHex: "deadbeef",
		UserIDHex:       " ",
		UserIDProvided:  true,
		Name:            "alice-new@example.com",
		NameProvided:    true,
	})
	if err != nil {
		t.Fatalf("BuildUpdateUserPreview: %v", err)
	}

	if preview.Proposed.UserIDHex != "0102" {
		t.Fatalf("Proposed.UserIDHex = %q, want fallback to current user ID", preview.Proposed.UserIDHex)
	}
}

func sampleInventoryReport() InventoryReport {
	return InventoryReport{
		Device: report.DeviceReport{DeviceID: "cred01"},
		Support: SupportReport{
			CredentialManagement: true,
		},
		Summary: InventorySummary{
			ExistingResidentCredentialsCount:             1,
			MaxPossibleRemainingResidentCredentialsCount: 8,
			TotalRPs:         1,
			TotalCredentials: 1,
		},
		Groups: []CredentialGroup{
			{
				RPID:   "example.com",
				RPName: "Example",
				Credentials: []CredentialRecord{
					{
						CredentialIDHex: "deadbeef",
						CredentialType:  "public-key",
						UserIDHex:       "0102",
						UserName:        "alice@example.com",
						DisplayName:     "Alice",
					},
				},
			},
		},
	}
}
