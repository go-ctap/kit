package runtime

import (
	"context"

	"github.com/go-ctap/kit/model"
)

type EventDispatcher struct {
	sink EventSink
}

type EventSink interface {
	Emit(context.Context, model.OperationEvent)
}

type noopEventSink struct{}

func (noopEventSink) Emit(context.Context, model.OperationEvent) {}

func NewEventDispatcher(sink EventSink) *EventDispatcher {
	if sink == nil {
		sink = noopEventSink{}
	}

	return &EventDispatcher{sink: sink}
}

func (d *EventDispatcher) Emit(ctx context.Context, event model.OperationEvent) {
	if d == nil || d.sink == nil {
		return
	}

	d.sink.Emit(ctx, event)
}
