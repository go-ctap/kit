package credentials

import (
	"testing"

	. "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

func TestFindByHexID(t *testing.T) {
	target, err := FindByHexID(sampleInventoryReport(), "deadbeef")
	if err != nil {
		t.Fatalf("FindByHexID: %v", err)
	}

	if target.RP.ID != "example.com" {
		t.Fatalf("RP.ID = %q, want example.com", target.RP.ID)
	}

	if target.User.UserIDHex != "0102" {
		t.Fatalf("UserIDHex = %q, want 0102", target.User.UserIDHex)
	}
}

func TestBuildDeletePreview(t *testing.T) {
	inventory := sampleInventoryReport()

	preview, err := BuildDeletePreview(inventory, "deadbeef")
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

	if preview.Warnings[1].Code != "credential.delete.associated_large_blob" {
		t.Fatalf("second warning code = %q, want credential.delete.associated_large_blob", preview.Warnings[1].Code)
	}
}

func TestBuildDeletePreviewMissingCredential(t *testing.T) {
	_, err := BuildDeletePreview(sampleInventoryReport(), "")
	if !failure.IsCode(err, failure.CodeCredentialIDRequired) {
		t.Fatalf("BuildDeletePreview(empty) error = %v, want %s", err, failure.CodeCredentialIDRequired)
	}

	if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
		t.Fatalf("BuildDeletePreview(empty) phase = %q, want %q", got, failure.PhaseValidation)
	}
}

func TestBuildUpdateUserPreviewKeepsUserID(t *testing.T) {
	target := sampleCredentialTarget(t)

	preview, err := BuildUpdateUserPreview(UpdateUserOperation{
		Target:       target,
		Name:         "alice-new@example.com",
		NameProvided: true,
	})
	if err != nil {
		t.Fatalf("BuildUpdateUserPreview: %v", err)
	}
	if preview.Proposed.UserIDHex != "0102" {
		t.Fatalf("Proposed.UserIDHex = %q, want unchanged user ID", preview.Proposed.UserIDHex)
	}
	if got := preview.Warnings[0]; got.Severity != safety.SeverityDestructive ||
		got.Code != "credential.update_user.mutation" {
		t.Fatalf("first warning = %#v, want destructive update warning", got)
	}
}

func TestBuildUpdateUserPreviewRequiresTargetAndChange(t *testing.T) {
	_, err := BuildUpdateUserPreview(UpdateUserOperation{NameProvided: true})
	if !failure.IsCode(err, failure.CodeCredentialIDRequired) {
		t.Fatalf("BuildUpdateUserPreview(empty target) error = %v, want %s", err, failure.CodeCredentialIDRequired)
	}

	_, err = ResolveUpdatedUser(UpdateUserOperation{})
	if !failure.IsCode(err, failure.CodeCredentialChangesRequired) {
		t.Fatalf("ResolveUpdatedUser(no changes) error = %v, want %s", err, failure.CodeCredentialChangesRequired)
	}
}

func sampleCredentialTarget(t *testing.T) CredentialTarget {
	t.Helper()

	target, err := FindByHexID(sampleInventoryReport(), "deadbeef")
	if err != nil {
		t.Fatalf("FindByHexID: %v", err)
	}

	return target
}

func sampleInventoryReport() InventoryReport {
	return InventoryReport{
		Device: report.DeviceReport{Fingerprint: "cred01"},
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
