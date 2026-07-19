package runtime

import (
	"context"

	"github.com/go-ctap/kit/model"
)

type EventDispatcher struct {
	sink model.EventSink
}

func NewEventDispatcher(sink model.EventSink) *EventDispatcher {
	if sink == nil {
		sink = model.NoopEventSink{}
	}

	return &EventDispatcher{sink: sink}
}

func (d *EventDispatcher) Emit(ctx context.Context, event model.OperationEvent) {
	if d == nil || d.sink == nil {
		return
	}

	d.sink.Emit(ctx, event)
}
