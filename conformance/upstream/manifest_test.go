package upstream_test

import (
	"strings"
	"testing"

	"github.com/go-ctap/kit/conformance/ctap23"
	"github.com/go-ctap/kit/conformance/upstream"
)

func TestCurrentManifestPinsExtractedCorpusAndPortMapping(t *testing.T) {
	manifest := upstream.Current()
	if manifest.Totals != (upstream.Counts{TestLists: 11, References: 252, Scripts: 219, Cases: 1977}) {
		t.Fatalf("totals = %+v", manifest.Totals)
	}
	if manifest.Source.Version != "1.9.1" || manifest.Source.Digest != "sha256:028729315ecd36f76b9166c014ae4af3c3dde41efcad99444b519c3a867cef43" {
		t.Fatalf("source = %#v", manifest.Source)
	}
	if len(manifest.Modules) != 7 {
		t.Fatalf("modules = %d, want 7", len(manifest.Modules))
	}
	if len(manifest.Ports) != 1 {
		t.Fatalf("ports = %#v, want first Go port", manifest.Ports)
	}

	port := manifest.Ports[0]
	suite := ctap23.Suite(ctap23.Config{})
	if suite.Source != manifest.Source {
		t.Fatalf("suite source = %#v, manifest source = %#v", suite.Source, manifest.Source)
	}
	if port.SuiteID != suite.ID || port.TestID != ctap23.TestIDAuthrGeneric1P1 || port.Source != suite.Tests[0].Source {
		t.Fatalf("port = %#v, suite/test source = %q/%q/%#v", port, suite.ID, suite.Tests[0].ID, suite.Tests[0].Source)
	}
	if port.Status != upstream.PortStatusPorted {
		t.Fatalf("port status = %q, want ported", port.Status)
	}
}

func TestValidateRejectsDriftedCountsAndMappings(t *testing.T) {
	manifest := upstream.Current()
	manifest.Totals.Cases--
	if err := upstream.Validate(manifest); err == nil || !strings.Contains(err.Error(), "module totals") {
		t.Fatalf("Validate count drift = %v", err)
	}

	manifest = upstream.Current()
	manifest.Ports[0].ModuleID = "missing"
	if err := upstream.Validate(manifest); err == nil || !strings.Contains(err.Error(), "unknown module") {
		t.Fatalf("Validate mapping drift = %v", err)
	}
}
