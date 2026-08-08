// These tests exercise the public assessment API as an external consumer.
package conformance_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

func TestAssessGetInfoJSONContractIsTypedAndDeterministic(t *testing.T) {
	valid := conformance.AssessGetInfo(validFIDO23Info())
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}

	text := string(raw)
	for _, want := range []string{`"advertisedProfiles":["FIDO_2_3"]`, `"findings":[]`, `"inconclusive":[]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON %s does not contain %s", text, want)
		}
	}

	for _, legacy := range []string{`"args"`, `"conformanceFindings"`, `"expectation"`} {
		if strings.Contains(text, legacy) {
			t.Fatalf("legacy field %s leaked into %s", legacy, text)
		}
	}
	unresolved, err := json.Marshal(conformance.AssessGetInfo(protocol.AuthenticatorGetInfoResponse{}))
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{`"target":null`, `"advertisedProfiles":[]`, `"findings":[]`, `"inconclusive":[]`} {
		if !strings.Contains(string(unresolved), want) {
			t.Fatalf("unresolved JSON %s does not contain %s", unresolved, want)
		}
	}

	info := validFIDO23Info()
	info.AuthenticatorConfigCommands = nil
	invalid := conformance.AssessGetInfo(info)
	for _, finding := range invalid.Findings {
		if len(finding.References) == 0 {
			t.Fatalf("finding has no normative references: %#v", finding)
		}

		for _, reference := range finding.References {
			if reference.Section == "9.7" || reference.Section == "9.8" {
				t.Fatalf("mandatory item encoded as a fake subsection: %#v", reference)
			}
		}
	}

	first, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}

	second, err := json.Marshal(conformance.AssessGetInfo(info))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(first, second) {
		t.Fatalf("JSON is not deterministic:\n%s\n%s", first, second)
	}

	if !strings.Contains(string(first), `"values":[]`) {
		t.Fatalf("empty typed values serialized as null: %s", first)
	}
}
