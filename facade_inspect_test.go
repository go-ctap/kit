package ctapkit

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/model"
)

func TestInspectEmitsNoEventsWithoutProgressOrStateChanges(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractSession(t, events, nil)
	defer func() { _ = session.Close() }()

	output, err := session.Run(context.Background(), model.InspectOperation{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := output.(model.InspectOutput); !ok {
		t.Fatalf("unexpected output: %#v", output)
	}

	recorded := events.Events()
	if len(recorded) != 0 {
		t.Fatalf("events = %v, want none", recorded)
	}
}
