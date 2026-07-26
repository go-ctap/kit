package workflow

import (
	"strings"
	"testing"

	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/safety"
)

func TestLargeBlobMutationWarningsDescribeFirstMatchingEntry(t *testing.T) {
	state := targetBlobState{currentBlobIndex: 0}
	tests := []struct {
		name      string
		operation applargeblobs.MutationOperation
		byteCount int
		arraySize int
	}{
		{name: "replace", operation: applargeblobs.MutationReplace, byteCount: 4, arraySize: 32},
		{name: "delete", operation: applargeblobs.MutationDelete, arraySize: 17},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preview := buildMutationPreview(state, test.operation, test.byteCount, test.arraySize, false)
			got := preview.Warnings[1].Message
			if !strings.Contains(got, "first large-blob entry") ||
				!strings.Contains(got, "additional matching entries remain unchanged") {
				t.Fatalf("warning = %q", got)
			}
		})
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
