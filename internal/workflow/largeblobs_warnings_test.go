package workflow

import (
	"strings"
	"testing"

	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/safety"
)

func TestLargeBlobMutationWarningsDescribeFirstMatchingEntry(t *testing.T) {
	state := targetBlobState{currentBlobIndex: 0}

	preview := buildMutationPreview(state, applargeblobs.MutationReplace, 4, 32, false)
	if got := preview.Warnings[1].Message; !strings.Contains(got, "first large-blob entry") ||
		!strings.Contains(got, "additional matching entries remain unchanged") {
		t.Fatalf("replace warning = %q", got)
	}

	preview = buildMutationPreview(state, applargeblobs.MutationDelete, 0, 17, false)
	if got := preview.Warnings[1].Message; !strings.Contains(got, "first large-blob entry") ||
		!strings.Contains(got, "additional matching entries remain unchanged") {
		t.Fatalf("delete warning = %q", got)
	}
}

func TestGarbageCollectionWarningDistinguishesNoop(t *testing.T) {
	runner := Runner{}

	preview := runner.buildGarbageCollectPreview(garbageCollectState{unmatchedCount: 1})
	if got := preview.Warnings[0]; got.Severity != safety.SeverityDestructive ||
		!strings.Contains(got.Message, "malformed entries are retained") {
		t.Fatalf("destructive GC warning = %#v", got)
	}

	preview = runner.buildGarbageCollectPreview(garbageCollectState{})
	if got := preview.Warnings[0]; got.Severity != safety.SeverityInfo ||
		got.Code != "large_blob.garbage_collect_noop" {
		t.Fatalf("no-op GC warning = %#v", got)
	}
}
