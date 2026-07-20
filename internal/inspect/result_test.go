package inspect

import (
	"testing"

	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/inspect"
	"github.com/go-ctap/kit/model/report"
)

func TestBuildResultIncludesGetInfoAssessment(t *testing.T) {
	result := BuildResult(report.DeviceReport{}, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
	})

	if len(result.Info.Assessment.Facts) == 0 {
		t.Fatal("assessment facts are empty")
	}

	for _, fact := range result.Info.Assessment.Facts {
		if fact.ID != model.FactIDClientPIN {
			continue
		}
		if fact.State != model.FactStateNotConfigured || fact.Value.Boolean == nil || *fact.Value.Boolean {
			t.Fatalf("client PIN fact = %#v, want reported not configured", fact)
		}

		return
	}

	t.Fatal("client PIN fact not found")
}
