package config

import (
	"errors"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/safety"
)

func TestBioEnrollPreviewAllowsSupportedAuthenticatorWithNoEnrollments(t *testing.T) {
	status := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll: false,
		},
	})

	preview, err := BuildBioEnrollPreview(status, 60000, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildBioEnrollPreview: %v", err)
	}
	if preview.PreviewOnly {
		t.Fatalf("unexpected preview: %#v", preview)
	}
}

func TestBioMutationPreviewRejectsKnownEmptyEnrollmentSet(t *testing.T) {
	status := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll: false,
		},
	})

	if _, err := BuildBioRenamePreview(status, "01", "left thumb", safety.PreviewModeDryRun); !errors.Is(err, ErrBioNoEnrollments) {
		t.Fatalf("BuildBioRenamePreview error = %v, want ErrBioNoEnrollments", err)
	}
	if _, err := BuildBioRemovePreview(status, "01", safety.PreviewModeDryRun); !errors.Is(err, ErrBioNoEnrollments) {
		t.Fatalf("BuildBioRemovePreview error = %v, want ErrBioNoEnrollments", err)
	}
}
