package ctapkit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	rtauthenticator "github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/discovery"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

type blockingIdentityResolver struct {
	provider report.Vendor
	identity *report.DeviceIdentity
	err      error
	started  chan struct{}
	release  chan struct{}
	calls    atomic.Int32
}

func (r *blockingIdentityResolver) Provider(discovery.Descriptor) report.Vendor {
	return r.provider
}

func (r *blockingIdentityResolver) Resolve(
	ctx context.Context,
	_ discovery.Descriptor,
) (*report.DeviceIdentity, report.Vendor, bool, error) {
	r.calls.Add(1)
	select {
	case r.started <- struct{}{}:
	default:
	}
	select {
	case <-r.release:
		return r.identity, r.provider, true, r.err
	case <-ctx.Done():
		return nil, r.provider, true, ctx.Err()
	}
}

type inventoryDiscoveryFunc func(context.Context, transport.Mode) ([]discovery.Descriptor, error)

func (f inventoryDiscoveryFunc) Discover(
	ctx context.Context,
	mode transport.Mode,
) ([]discovery.Descriptor, error) {
	return f(ctx, mode)
}

type inventoryTestLifecycle struct{}

func (inventoryTestLifecycle) Close() error { return nil }

func recordInventoryOpen(called chan<- struct{}) authenticatorOpenFunc {
	return func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		called <- struct{}{}

		return &rtauthenticator.Opened{Lifecycle: inventoryTestLifecycle{}}, nil
	}
}

func newTestInventory(
	t *testing.T,
	resolver identityResolver,
	open authenticatorOpenFunc,
) *Inventory {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	close(monitorDone)
	inventory := &Inventory{
		mode:        transport.ModeHID,
		identity:    resolver,
		open:        open,
		ctx:         ctx,
		cancel:      cancel,
		events:      make(chan InventoryEvent, 1),
		monitorDone: monitorDone,
		records:     make(map[report.AttachmentID]*inventoryRecord),
	}
	t.Cleanup(func() {
		if err := inventory.Close(); err != nil {
			t.Errorf("close inventory: %v", err)
		}
	})
	return inventory
}

func TestInventoryPublishesAttachmentBeforeIdentity(t *testing.T) {
	resolver := &blockingIdentityResolver{
		provider: report.VendorToken2,
		identity: &report.DeviceIdentity{
			Vendor: report.VendorToken2,
			Model:  "Token2 card",
			Serial: "66202208969539",
		},
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	inventory := newTestInventory(t, resolver, nil)
	descriptor := discovery.Descriptor{
		Transport: transport.ModeHID,
		Path:      "hid-1",
		VendorID:  0x349e,
	}

	inventory.applyDescriptors([]discovery.Descriptor{descriptor})
	before := inventory.Snapshot()
	if len(before.Devices) != 1 {
		t.Fatalf("initial devices = %d, want 1", len(before.Devices))
	}
	id := before.Devices[0].Attachment.ID
	if before.Devices[0].Resolution.State != report.IdentityResolving {
		t.Fatalf("initial resolution = %q, want resolving", before.Devices[0].Resolution.State)
	}
	if before.Devices[0].Identity != nil {
		t.Fatal("identity published before resolver completed")
	}

	<-resolver.started
	close(resolver.release)
	event := <-inventory.Events()
	after := event.Snapshot
	if event.Trigger != InventoryTriggerIdentity {
		t.Fatalf("trigger = %q, want identity", event.Trigger)
	}
	if after.Devices[0].Attachment.ID != id {
		t.Fatalf("attachment ID changed from %q to %q", id, after.Devices[0].Attachment.ID)
	}
	if after.Devices[0].Identity == nil ||
		after.Devices[0].Identity.Serial != "66202208969539" {
		t.Fatalf("resolved identity = %#v", after.Devices[0].Identity)
	}
}

func TestInventoryOpenWaitsForExistingResolveTask(t *testing.T) {
	resolveErr := errors.New("optional identity failed")
	resolver := &blockingIdentityResolver{
		provider: report.VendorToken2,
		err:      resolveErr,
		started:  make(chan struct{}, 2),
		release:  make(chan struct{}),
	}
	openCalled := make(chan struct{}, 1)
	inventory := newTestInventory(t, resolver, recordInventoryOpen(openCalled))
	inventory.applyDescriptors([]discovery.Descriptor{
		{
			Transport: transport.ModeSmartCard,
			Path:      "reader-1",
			ATR:       []byte{0x01},
		},
		{
			Transport: transport.ModeHID,
			Path:      "hid-2",
			VendorID:  0x349e,
		},
	})
	id := inventory.Snapshot().Devices[0].Attachment.ID
	for range 2 {
		select {
		case <-resolver.started:
		case <-time.After(time.Second):
			t.Fatal("identity tasks did not start concurrently")
		}
	}

	opened := make(chan *Authenticator, 1)
	openErrors := make(chan error, 1)
	go func() {
		authenticator, err := inventory.OpenAuthenticator(context.Background(), id)
		opened <- authenticator
		openErrors <- err
	}()

	select {
	case <-openCalled:
		t.Fatal("authenticator opened while identity task was pending")
	case <-time.After(20 * time.Millisecond):
	}

	close(resolver.release)
	authenticator := <-opened
	if err := <-openErrors; err != nil {
		t.Fatalf("open after identity failure: %v", err)
	}
	if resolver.calls.Load() != 2 {
		t.Fatalf("resolve calls = %d, want 2", resolver.calls.Load())
	}
	if authenticator == nil {
		t.Fatal("open returned nil authenticator")
	}
	if err := authenticator.Close(); err != nil {
		t.Fatalf("close authenticator: %v", err)
	}
}

func TestInventoryHIDOpenDoesNotWaitForIdentity(t *testing.T) {
	resolver := &blockingIdentityResolver{
		provider: report.VendorToken2,
		started:  make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
	openCalled := make(chan struct{}, 1)
	inventory := newTestInventory(t, resolver, recordInventoryOpen(openCalled))
	inventory.applyDescriptors([]discovery.Descriptor{{
		Transport: transport.ModeHID,
		Path:      "hid-1",
		VendorID:  0x349e,
	}})
	id := inventory.Snapshot().Devices[0].Attachment.ID
	<-resolver.started
	inventory.mu.Lock()
	resolveDone := inventory.records[id].done
	inventory.mu.Unlock()

	authenticator, err := inventory.OpenAuthenticator(t.Context(), id)
	if err != nil {
		t.Fatalf("open while identity pending: %v", err)
	}
	select {
	case <-openCalled:
	default:
		t.Fatal("HID authenticator did not open while optional identity was pending")
	}
	if err := authenticator.Close(); err != nil {
		t.Fatalf("close authenticator: %v", err)
	}
	if err := inventory.Close(); err != nil {
		t.Fatalf("close inventory: %v", err)
	}
	select {
	case <-resolveDone:
	default:
		t.Fatal("close returned before identity task finished")
	}
}

func TestInventoryRemovalRejectsLateIdentity(t *testing.T) {
	resolver := &blockingIdentityResolver{
		provider: report.VendorToken2,
		identity: &report.DeviceIdentity{
			Vendor: report.VendorToken2,
			Serial: "stale",
		},
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	inventory := newTestInventory(t, resolver, nil)
	inventory.applyDescriptors([]discovery.Descriptor{{
		Transport: transport.ModeHID,
		Path:      "hid-1",
		VendorID:  0x349e,
	}})
	<-resolver.started
	id := inventory.Snapshot().Devices[0].Attachment.ID
	inventory.mu.Lock()
	record := inventory.records[id]
	inventory.mu.Unlock()

	inventory.applyDescriptors(nil)
	close(resolver.release)
	<-record.done
	if devices := inventory.Snapshot().Devices; len(devices) != 0 {
		t.Fatalf("late identity restored removed attachment: %#v", devices)
	}
	select {
	case event := <-inventory.Events():
		t.Fatalf("late identity published an event: %#v", event)
	default:
	}
}

func TestInventoryReplacesIdentityWhenConnectionEvidenceChanges(t *testing.T) {
	resolver := &blockingIdentityResolver{
		provider: report.VendorToken2,
		started:  make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
	inventory := newTestInventory(t, resolver, nil)
	first := discovery.Descriptor{
		Transport: transport.ModeSmartCard,
		Path:      "reader-1",
		ATR:       []byte{0x01},
	}

	inventory.applyDescriptors([]discovery.Descriptor{first})
	<-resolver.started
	firstDevice := inventory.Snapshot().Devices[0]
	inventory.mu.Lock()
	firstRecord := inventory.records[firstDevice.Attachment.ID]
	firstRecord.device.report.Identity = &report.DeviceIdentity{Serial: "stale"}
	inventory.mu.Unlock()

	second := first
	second.ATR = []byte{0x02}
	inventory.applyDescriptors([]discovery.Descriptor{second})
	secondDevice := inventory.Snapshot().Devices[0]
	if secondDevice.Attachment.ID != firstDevice.Attachment.ID {
		t.Fatalf(
			"attachment ID changed from %q to %q",
			firstDevice.Attachment.ID,
			secondDevice.Attachment.ID,
		)
	}
	if secondDevice.Identity != nil {
		t.Fatalf("replacement retained stale identity %#v", secondDevice.Identity)
	}

	inventory.mu.Lock()
	secondRecord := inventory.records[secondDevice.Attachment.ID]
	inventory.mu.Unlock()
	if secondRecord == firstRecord {
		t.Fatal("connection evidence change did not replace the inventory record")
	}
}

func TestInventorySerializesScans(t *testing.T) {
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})

	inventory := newTestInventory(t, &blockingIdentityResolver{provider: report.VendorUnknown}, nil)
	inventory.discovery = inventoryDiscoveryFunc(func(
		ctx context.Context,
		_ transport.Mode,
	) ([]discovery.Descriptor, error) {
		call := calls.Add(1)
		path := "newer"
		if call == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			path = "older"
		}

		return []discovery.Descriptor{{
			Transport: transport.ModeHID,
			Path:      path,
		}}, nil
	})

	done := make(chan error, 2)
	go func() {
		done <- inventory.scan(t.Context(), InventoryTriggerTopology)
	}()
	<-firstStarted

	secondLaunched := make(chan struct{})
	go func() {
		close(secondLaunched)
		done <- inventory.Refresh(t.Context())
	}()
	<-secondLaunched
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent discovery calls = %d, want 1", got)
	}

	close(releaseFirst)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("scan: %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("discovery calls = %d, want 2", got)
	}

	snapshot := inventory.Snapshot()
	if len(snapshot.Devices) != 1 {
		t.Fatalf("final devices = %d, want 1", len(snapshot.Devices))
	}
	expectedID := attachmentReport(discovery.Descriptor{
		Transport: transport.ModeHID,
		Path:      "newer",
	}).ID
	if snapshot.Devices[0].Attachment.ID != expectedID {
		t.Fatalf(
			"final attachment = %q, want %q",
			snapshot.Devices[0].Attachment.ID,
			expectedID,
		)
	}
}
