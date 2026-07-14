package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/model/failure"
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

	if _, err := BuildBioRenamePreview(status, "01", "left thumb", safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeBioNoEnrollments) {
		t.Fatalf("BuildBioRenamePreview error = %v, want %s", err, failure.CodeBioNoEnrollments)
	}
	if _, err := BuildBioRemovePreview(status, "01", safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeBioNoEnrollments) {
		t.Fatalf("BuildBioRemovePreview error = %v, want %s", err, failure.CodeBioNoEnrollments)
	}
}

func TestBioEnrollJSONPreservesExplicitZeroRemainingSamples(t *testing.T) {
	result := BioEnrollResult{
		TemplateIDHex:    "abcd",
		RemainingSamples: new(uint(0)),
		Samples: []BioEnrollSample{
			{Status: "good", RemainingSamples: new(uint(0))},
		},
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if got := strings.Count(string(raw), `"remainingSamples":0`); got != 2 {
		t.Fatalf("JSON = %s, want two explicit zero remainingSamples fields", raw)
	}

	raw, err = json.Marshal(BioEnrollResult{TemplateIDHex: "abcd"})
	if err != nil {
		t.Fatalf("Marshal absent: %v", err)
	}
	if strings.Contains(string(raw), "remainingSamples") {
		t.Fatalf("JSON = %s, want absent remainingSamples omitted", raw)
	}
}
