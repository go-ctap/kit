package devicewatch

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/kit/transport"
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
	if !got[0].Connected ||
		got[0].Candidate.Path != "fido-reader" ||
		got[0].Candidate.SmartCardInterface != transport.SmartCardInterfaceContactless {
		t.Fatalf("connected event = %#v, want fido-reader", got[0])
	}
	if got[1].Connected ||
		got[1].Candidate.Path != "fido-reader" ||
		got[1].Candidate.SmartCardInterface != transport.SmartCardInterfaceContactless {
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
	if candidate.SmartCardInterface != transport.SmartCardInterfaceContactless {
		t.Fatalf("smart-card interface = %q", candidate.SmartCardInterface)
	}
	if current := w.pcscCurrent["fido-reader"]; current.Path != candidate.Path {
		t.Fatalf("current candidate = %#v, want %#v", current, candidate)
	}
}

func TestSmartCardInterface(t *testing.T) {
	tests := []struct {
		name  string
		value pcsc.CardInterface
		want  transport.SmartCardInterface
	}{
		{
			name:  "contact",
			value: pcsc.CardInterfaceContact,
			want:  transport.SmartCardInterfaceContact,
		},
		{
			name:  "contactless",
			value: pcsc.CardInterfaceContactless,
			want:  transport.SmartCardInterfaceContactless,
		},
		{
			name:  "unknown",
			value: pcsc.CardInterfaceUnknown,
			want:  transport.SmartCardInterfaceUnknown,
		},
		{
			name:  "future",
			value: pcsc.CardInterface("future"),
			want:  transport.SmartCardInterfaceUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := smartCardInterface(tt.value); got != tt.want {
				t.Fatalf("interface = %q, want %q", got, tt.want)
			}
		})
	}
}

func fakeSmartCardProbe(accepted string) func(
	context.Context,
	string,
) (transport.SmartCardInterface, error) {
	return func(_ context.Context, reader string) (transport.SmartCardInterface, error) {
		if reader != accepted {
			return "", errors.New("FIDO applet unavailable")
		}

		return transport.SmartCardInterfaceContactless, nil
	}
}
