package ctapkit

import (
	"context"
	"testing"
)

func TestInspectEmitsNoEventsWithoutProgressOrStateChanges(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractAuthenticator(t, events, nil)
	defer func() { _ = session.Close() }()

	output, err := session.Inspect(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if output.Device.Attachment.ID == "" {
		t.Fatalf("unexpected output: %#v", output)
	}

	recorded := events.Events()
	if len(recorded) != 0 {
		t.Fatalf("events = %v, want none", recorded)
	}
}
