package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ghid "github.com/go-ctap/hid"
	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func TestDiscoveryEventFromHID(t *testing.T) {
	tests := []struct {
		name  string
		event ghid.DeviceEvent
		want  bool
	}{
		{
			name: "fido",
			event: ghid.DeviceEvent{
				Type:       ghid.DeviceEventConnected,
				DeviceInfo: &ghid.DeviceInfo{UsagePage: fidoUsagePage, Usage: fidoUsage},
			},
			want: true,
		},
		{
			name: "non fido",
			event: ghid.DeviceEvent{
				Type:       ghid.DeviceEventConnected,
				DeviceInfo: &ghid.DeviceInfo{UsagePage: 1, Usage: 2},
			},
		},
		{
			name: "partial metadata",
			event: ghid.DeviceEvent{
				Type:       ghid.DeviceEventDisconnected,
				DeviceInfo: &ghid.DeviceInfo{Path: "hid://one"},
				Err:        errors.New("metadata unavailable"),
			},
			want: true,
		},
		{
			name:  "missing metadata",
			event: ghid.DeviceEvent{Type: ghid.DeviceEventDisconnected},
			want:  true,
		},
		{
			name:  "unknown event",
			event: ghid.DeviceEvent{Type: "changed"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isFIDOEvent(test.event)
			if got != test.want {
				t.Fatalf("accepted = %v, want %v", got, test.want)
			}
		})
	}
}

func TestTopologyReconciliationClosesOnlyMissingSession(t *testing.T) {
	firstDevice := testDevice("hid://one", "serial-1")
	secondDevice := testDevice("hid://two", "serial-2")
	firstRuntime := &fakeSessionRuntime{info: model.SessionInfo{Device: firstDevice}}
	secondRuntime := &fakeSessionRuntime{info: model.SessionInfo{Device: secondDevice}}
	service := New()
	service.sessions["session-1"] = managedTestSession("session-1", firstDevice, firstRuntime)
	service.sessions["session-2"] = managedTestSession("session-2", secondDevice, secondRuntime)

	service.mu.Lock()
	affected := service.detachMissingSessionsLocked([]report.DeviceReport{secondDevice})
	service.mu.Unlock()
	err := service.closeManagedSessions(affected)
	if err != nil {
		t.Fatalf("close sessions: %v", err)
	}

	if !firstRuntime.closed.Load() || secondRuntime.closed.Load() {
		t.Fatalf("runtime close state = (%v, %v)", firstRuntime.closed.Load(), secondRuntime.closed.Load())
	}
	if _, ok := service.sessions["session-2"]; !ok {
		t.Fatal("surviving session was removed")
	}
}

func TestDiscoverUsesReconcilerForExistingSessions(t *testing.T) {
	device := testDevice("hid://one", "serial-1")
	runtime := &fakeSessionRuntime{info: model.SessionInfo{Device: device}}
	service := New()
	service.sessions["session-1"] = managedTestSession("session-1", device, runtime)
	service.scanDevices = func(context.Context, ...ctapkit.DiscoverOption) ([]ctapkit.Device, error) {
		return nil, nil
	}

	snapshot, err := service.Discover(context.Background(), DiscoverRequest{Mode: transport.ModeHID})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(snapshot.Devices) != 0 || !runtime.closed.Load() {
		t.Fatalf("snapshot = %#v, runtime closed = %v", snapshot, runtime.closed.Load())
	}
}

func TestRefreshDiscoveryPublishesFailureAndRetainsMode(t *testing.T) {
	emitter := &recordingEmitter{events: make(chan DiscoveryChangedEnvelope, 1)}
	service := New(WithEventEmitter(emitter))
	service.lastDiscoverMode = transport.ModeHID
	service.scanDevices = func(context.Context, ...ctapkit.DiscoverOption) ([]ctapkit.Device, error) {
		return nil, failure.New(
			failure.CodeTransportFailure,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	if err := service.RefreshDiscovery(context.Background(), DiscoverRequest{}); err != nil {
		t.Fatalf("RefreshDiscovery: %v", err)
	}
	if service.lastDiscoverMode != transport.ModeHID {
		t.Fatalf("last mode = %q, want HID", service.lastDiscoverMode)
	}

	select {
	case emitted := <-emitter.events:
		if emitted.Trigger != DiscoveryTriggerManual || emitted.Snapshot != nil ||
			emitted.Error == nil || emitted.Error.Code != failure.CodeTransportFailure ||
			emitted.Error.Phase != failure.PhaseDiscovery {
			t.Fatalf("failure envelope = %#v", emitted)
		}
	case <-time.After(time.Second):
		t.Fatal("manual discovery event was not emitted")
	}
}

func TestDiscoveryEventFollowsOperationCancellation(t *testing.T) {
	device := testDevice("hid://one", "serial-1")
	operationID := OperationID("operation-1")
	var canceled atomic.Bool
	observed := make(chan bool, 1)
	service := New(WithEventEmitter(eventEmitterFunc(func(name string, payload any) {
		if name == EventDiscoveryChanged {
			observed <- canceled.Load()
		}
	})))
	service.sessions["session-1"] = managedTestSession(
		"session-1",
		device,
		&fakeSessionRuntime{info: model.SessionInfo{Device: device}},
	)
	operation := &operationState{
		id:        operationID,
		sessionID: "session-1",
		done:      make(chan struct{}),
	}
	var cancelOnce sync.Once
	operation.cancel = func() {
		cancelOnce.Do(func() {
			canceled.Store(true)
			service.unregisterOperation(operationID)
		})
	}
	service.operations[operationID] = operation
	service.scanDevices = func(context.Context, ...ctapkit.DiscoverOption) ([]ctapkit.Device, error) {
		return nil, nil
	}

	err := service.reconcileTopology(
		context.Background(),
		DiscoverRequest{Mode: transport.ModeHID},
		DiscoveryTriggerHotplug,
		true,
	)
	if err != nil {
		t.Fatalf("reconcile topology: %v", err)
	}

	select {
	case wasCanceled := <-observed:
		if !wasCanceled {
			t.Fatal("event was emitted before cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("discovery event was not emitted")
	}
}

func TestDiscoveryMonitorCoalescesHIDBurst(t *testing.T) {
	receiver := &fakeDiscoveryReceiver{events: make(chan ghid.DeviceEvent, 8)}
	service := New()
	var opens atomic.Int32
	service.openMonitor = func() (ghid.EventReceiver, error) {
		opens.Add(1)
		return receiver, nil
	}
	scans := make(chan struct{}, 8)
	service.scanDevices = func(context.Context, ...ctapkit.DiscoverOption) ([]ctapkit.Device, error) {
		scans <- struct{}{}
		return nil, nil
	}

	if err := service.StartDiscoveryMonitoring(context.Background()); err != nil {
		t.Fatalf("StartDiscoveryMonitoring: %v", err)
	}
	if err := service.StartDiscoveryMonitoring(context.Background()); err != nil {
		t.Fatalf("second StartDiscoveryMonitoring: %v", err)
	}
	if opens.Load() != 1 {
		t.Fatalf("monitor opens = %d, want 1", opens.Load())
	}
	waitForScan(t, scans)

	info := &ghid.DeviceInfo{Path: "hid://one", UsagePage: fidoUsagePage, Usage: fidoUsage}
	receiver.events <- ghid.DeviceEvent{Type: ghid.DeviceEventConnected, DeviceInfo: info}
	receiver.events <- ghid.DeviceEvent{Type: ghid.DeviceEventDisconnected, DeviceInfo: info}
	receiver.events <- ghid.DeviceEvent{Type: ghid.DeviceEventConnected, DeviceInfo: info}
	waitForScan(t, scans)
	select {
	case <-scans:
		t.Fatal("HID burst caused more than one rescan")
	case <-time.After(2 * discoveryEventSettleTime):
	}

	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !receiver.isClosed() {
		t.Fatal("HID receiver was not closed")
	}
}

func TestServiceDoesNotEmitAfterClose(t *testing.T) {
	emitter := &recordingEmitter{events: make(chan DiscoveryChangedEnvelope, 1)}
	service := New(WithEventEmitter(emitter))
	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	service.emit(EventDiscoveryChanged, DiscoveryChangedEnvelope{
		Trigger: DiscoveryTriggerHotplug,
	})

	select {
	case event := <-emitter.events:
		t.Fatalf("event emitted after close: %#v", event)
	default:
	}
}

func TestDeviceReportPresentUsesTransportAndDeviceID(t *testing.T) {
	first := testDevice("hid://old", "serial-1")
	second := first
	second.Path = "hid://new"
	if !deviceReportPresent([]report.DeviceReport{first}, second) {
		t.Fatal("stable device did not survive path change")
	}
	second.Transport = transport.ModeWindowsProxy
	if deviceReportPresent([]report.DeviceReport{first}, second) {
		t.Fatal("devices on different transports matched")
	}
}

func testDevice(path string, serial string) report.DeviceReport {
	return report.DeviceReport{
		DeviceID:  serial,
		StableID:  serial != "",
		Transport: transport.ModeHID,
		Path:      path,
		Serial:    serial,
		VendorID:  1,
		ProductID: 2,
	}
}

func managedTestSession(id SessionID, device report.DeviceReport, runtime sessionRuntime) *managedSession {
	return &managedSession{id: id, device: device, session: runtime}
}

func waitForScan(t *testing.T, scans <-chan struct{}) {
	t.Helper()
	select {
	case <-scans:
	case <-time.After(time.Second):
		t.Fatal("discovery scan did not run")
	}
}

type recordingEmitter struct {
	events chan DiscoveryChangedEnvelope
}

func (e *recordingEmitter) Emit(name string, payload any) {
	if name != EventDiscoveryChanged {
		return
	}
	if envelope, ok := payload.(DiscoveryChangedEnvelope); ok {
		e.events <- envelope
	}
}

type eventEmitterFunc func(name string, payload any)

func (f eventEmitterFunc) Emit(name string, payload any) {
	f(name, payload)
}

type fakeDiscoveryReceiver struct {
	events chan ghid.DeviceEvent
	once   sync.Once
	closed atomic.Bool
}

func (r *fakeDiscoveryReceiver) Listen() <-chan ghid.DeviceEvent {
	return r.events
}

func (r *fakeDiscoveryReceiver) Close() error {
	r.once.Do(func() {
		r.closed.Store(true)
		close(r.events)
	})
	return nil
}

func (r *fakeDiscoveryReceiver) isClosed() bool {
	return r.closed.Load()
}

type fakeSessionRuntime struct {
	info     model.SessionInfo
	closed   atomic.Bool
	closeErr error
}

func (s *fakeSessionRuntime) Run(
	context.Context,
	model.Operation,
	model.InteractionHandler,
	...ctapkit.RunOption,
) (model.OperationResult, error) {
	return nil, nil
}

func (s *fakeSessionRuntime) Close() error {
	s.closed.Store(true)
	return s.closeErr
}

func (s *fakeSessionRuntime) Info() model.SessionInfo {
	return s.info
}
