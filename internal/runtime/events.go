package runtime

import "github.com/go-ctap/kit/model"

type EventDispatcher struct {
	sink model.EventSink
}

func NewEventDispatcher(sink model.EventSink) *EventDispatcher {
	if sink == nil {
		sink = model.NoopEventSink{}
	}

	return &EventDispatcher{sink: sink}
}

func (d *EventDispatcher) Emit(event model.OperationEvent) {
	if d == nil || d.sink == nil {
		return
	}

	d.sink.Emit(event)
}
