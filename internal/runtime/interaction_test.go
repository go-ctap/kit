package runtime

import (
	"context"
	"testing"

	"github.com/go-ctap/kit/model"
)

type interactionHandlerFunc func(model.InteractionRequest) (model.InteractionResponse, error)

func (f interactionHandlerFunc) RequestInteraction(req model.InteractionRequest) (model.InteractionResponse, error) {
	return f(req)
}

func TestRequestInteractionPassesPromptPayloadOnly(t *testing.T) {
	events := &recordingEventSink{}
	var got model.InteractionRequest

	broker := NewInteractionBroker(events, interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		got = req

		return model.InteractionResponse{
			Confirmed: true,
		}, nil
	}))

	req := model.InteractionRequest{
		Kind:        model.InteractionKindConfirm,
		Message:     "confirm?",
		Destructive: true,
	}

	response, err := broker.RequestInteraction(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestInteraction: %v", err)
	}

	if got != req {
		t.Fatalf("handler request = %#v, want %#v", got, req)
	}

	if !response.Confirmed {
		t.Fatal("response confirmed = false, want true")
	}

	if len(events.events) != 1 {
		t.Fatalf("events = %d, want 1", len(events.events))
	}

	event := events.events[0]
	if event.Kind != req.Kind || event.Message != req.Message {
		t.Fatalf("interaction event = %#v, want kind/message from request", event)
	}
}

type recordingEventSink struct {
	events []model.OperationEvent
}

func (s *recordingEventSink) Emit(event model.OperationEvent) {
	s.events = append(s.events, event)
}
