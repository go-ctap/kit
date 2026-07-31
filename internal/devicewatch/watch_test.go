package devicewatch

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/pcsc"
)

func TestWatcherPublishesOnlyFIDOSmartCards(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	pcscEvents := make(chan pcsc.DeviceEvent, 4)
	w := &watcher{
		ctx:            ctx,
		cancel:         cancel,
		events:         make(chan Event),
		done:           make(chan struct{}),
		pcscEvents:     pcscEvents,
		pcscCurrent:    make(map[string]Candidate),
		probeSmartCard: fakeSmartCardProbe("fido-reader"),
	}
	go w.run()

	ccid := &pcsc.ReaderInfo{Name: "ccid-reader", State: pcsc.ReaderStatePresent}
	fido := &pcsc.ReaderInfo{Name: "fido-reader", State: pcsc.ReaderStatePresent}
	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardInserted,
		ReaderInfo: ccid,
	}
	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardInserted,
		ReaderInfo: fido,
	}
	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardRemoved,
		ReaderInfo: ccid,
	}
	pcscEvents <- pcsc.DeviceEvent{
		Type:       pcsc.DeviceEventCardRemoved,
		ReaderInfo: fido,
	}
	close(pcscEvents)

	var got []Event
	for event := range w.events {
		got = append(got, event)
	}

	if len(got) != 2 {
		t.Fatalf("events = %#v, want FIDO connect and disconnect", got)
	}
	if !got[0].Connected || got[0].Candidate.Path != "fido-reader" {
		t.Fatalf("connected event = %#v, want fido-reader", got[0])
	}
	if got[1].Connected || got[1].Candidate.Path != "fido-reader" {
		t.Fatalf("disconnected event = %#v, want fido-reader", got[1])
	}
}

func TestWatcherInitialSmartCardsIncludeOnlyFIDO(t *testing.T) {
	w := &watcher{
		ctx:            t.Context(),
		pcscCurrent:    make(map[string]Candidate),
		probeSmartCard: fakeSmartCardProbe("fido-reader"),
	}

	if _, ok := w.connectSmartCard(&pcsc.ReaderInfo{Name: "ccid-reader"}); ok {
		t.Fatal("non-FIDO smart card became a candidate")
	}
	candidate, ok := w.connectSmartCard(&pcsc.ReaderInfo{Name: "fido-reader"})
	if !ok {
		t.Fatal("FIDO smart card was rejected")
	}
	if current := w.pcscCurrent["fido-reader"]; current.Path != candidate.Path {
		t.Fatalf("current candidate = %#v, want %#v", current, candidate)
	}
}

func fakeSmartCardProbe(accepted string) func(context.Context, string) error {
	return func(_ context.Context, reader string) error {
		if reader != accepted {
			return errors.New("FIDO applet unavailable")
		}

		return nil
	}
}
