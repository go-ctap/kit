package ctapkit

import (
	"context"
	"sync"
	"time"

	rtauthenticator "github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/discovery"
	rtidentity "github.com/go-ctap/kit/internal/identity"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

const (
	identityTimeout      = 2 * time.Second
	inventorySettleDelay = 100 * time.Millisecond
)

type InventoryTrigger string

const (
	InventoryTriggerTopology InventoryTrigger = "topology"
	InventoryTriggerIdentity InventoryTrigger = "identity"
	InventoryTriggerManual   InventoryTrigger = "manual"
)

type InventorySnapshot struct {
	Devices []report.DeviceReport `json:"devices"`
}

type InventoryEvent struct {
	Trigger  InventoryTrigger  `json:"trigger"`
	Snapshot InventorySnapshot `json:"snapshot"`
	Error    *failure.Failure  `json:"error,omitempty"`
}

type identityResolver interface {
	Provider(discovery.Descriptor) report.Vendor
	Resolve(
		context.Context,
		discovery.Descriptor,
	) (*report.DeviceIdentity, report.Vendor, bool, error)
}

type inventoryDiscovery interface {
	Discover(context.Context, transport.Mode) ([]discovery.Descriptor, error)
}

type inventoryRecord struct {
	device     attachment
	resolveCtx context.Context
	cancel     context.CancelFunc
	done       chan struct{}
}

// Inventory owns transport monitoring, attachment topology and optional
// identity resolution for one fixed transport mode.
type Inventory struct {
	mode        transport.Mode
	discovery   inventoryDiscovery
	identity    identityResolver
	open        authenticatorOpenFunc
	ctx         context.Context
	cancel      context.CancelFunc
	events      chan InventoryEvent
	monitor     <-chan discovery.Event
	monitorDone chan struct{}
	closeOnce   sync.Once

	scanMu    sync.Mutex
	resolvers sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	records map[report.AttachmentID]*inventoryRecord
	order   []report.AttachmentID
}

// OpenInventory performs the initial attachment scan and starts transport
// monitoring and progressive identity resolution.
//
//goland:noinspection GoUnusedExportedFunction
func OpenInventory(ctx context.Context, mode transport.Mode) (*Inventory, error) {
	if mode == "" {
		mode = transport.ModeAuto
	}

	lifetime, cancel := context.WithCancel(context.Background())
	source := discovery.New()
	inventory := &Inventory{
		mode:        mode,
		discovery:   source,
		identity:    rtidentity.NewResolver(),
		open:        rtauthenticator.Open,
		ctx:         lifetime,
		cancel:      cancel,
		events:      make(chan InventoryEvent, 1),
		monitorDone: make(chan struct{}),
		records:     make(map[report.AttachmentID]*inventoryRecord),
	}

	monitor, err := source.Events(lifetime, mode)
	if err != nil {
		cancel()
		return nil, err
	}
	inventory.monitor = monitor

	descriptors, err := inventory.discovery.Discover(ctx, mode)
	if err != nil {
		cancel()
		return nil, err
	}
	inventory.applyDescriptors(descriptors)

	go inventory.runMonitor()

	return inventory, nil
}

// Snapshot returns the current typed inventory state.
func (i *Inventory) Snapshot() InventorySnapshot {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.snapshotLocked()
}

// Events returns full snapshots for topology, manual refresh and identity
// changes. The channel closes when Inventory closes.
func (i *Inventory) Events() <-chan InventoryEvent {
	return i.events
}

// Refresh performs one authoritative attachment scan. Failed optional identity
// does not turn a successful topology refresh into an error.
func (i *Inventory) Refresh(ctx context.Context) error {
	return i.scan(ctx, InventoryTriggerManual)
}

func (i *Inventory) scan(ctx context.Context, trigger InventoryTrigger) error {
	i.scanMu.Lock()
	defer i.scanMu.Unlock()

	i.mu.Lock()
	closed := i.closed
	i.mu.Unlock()
	if closed {
		return failure.New(
			failure.CodeOperationCanceled,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	descriptors, err := i.discovery.Discover(ctx, i.mode)
	if err != nil {
		return err
	}
	i.applyDescriptors(descriptors)
	i.publish(trigger, nil)

	return nil
}

// OpenAuthenticator opens CTAP for one current attachment. Smart-card opens
// wait for the attachment's identity task to release its exclusive PC/SC
// access. HID opens use an independent CTAPHID channel and do not wait for
// optional identity.
func (i *Inventory) OpenAuthenticator(
	ctx context.Context,
	id report.AttachmentID,
	opts ...AuthenticatorOption,
) (*Authenticator, error) {
	i.mu.Lock()
	record := i.records[id]
	if record == nil || i.closed {
		i.mu.Unlock()
		return nil, failure.New(
			failure.CodeDeviceNotFound,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}
	var done <-chan struct{}
	if record.device.descriptor.Transport == transport.ModeSmartCard {
		done = record.done
	}
	i.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return nil, NormalizeError(ctx.Err(), failure.PhaseAuthenticator)
		}
	}

	i.mu.Lock()
	current := i.records[id]
	if current != record || i.closed {
		i.mu.Unlock()
		return nil, failure.New(
			failure.CodeDeviceNotFound,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}
	device := current.device
	i.mu.Unlock()

	return openAuthenticatorHandle(ctx, device, i.open, opts...)
}

// Close stops monitoring and resolution. Authenticators opened from Inventory
// remain owned by their callers and must be closed before Inventory.
func (i *Inventory) Close() error {
	i.closeOnce.Do(func() {
		i.stop()
		i.resolvers.Wait()
		<-i.monitorDone
		close(i.events)
	})

	return nil
}

func (i *Inventory) stop() {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return
	}
	i.closed = true
	for _, record := range i.records {
		record.cancel()
	}
	i.mu.Unlock()
	i.cancel()
}

func (i *Inventory) applyDescriptors(descriptors []discovery.Descriptor) {
	type pendingIdentity struct {
		record     *inventoryRecord
		id         report.AttachmentID
		descriptor discovery.Descriptor
	}
	var pending []pendingIdentity

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return
	}

	next := make(map[report.AttachmentID]*inventoryRecord, len(descriptors))
	order := make([]report.AttachmentID, 0, len(descriptors))
	for _, descriptor := range descriptors {
		attachmentInfo := attachmentReport(descriptor)
		id := attachmentInfo.ID
		order = append(order, id)
		existing := i.records[id]
		if existing != nil && sameConnection(existing.device.descriptor, descriptor) {
			existing.device.descriptor = descriptor
			existing.device.report.Attachment = attachmentInfo
			next[id] = existing
			continue
		}
		if existing != nil {
			existing.cancel()
		}

		resolveCtx, cancel := context.WithCancel(i.ctx)
		provider := i.identity.Provider(descriptor)
		state := report.IdentityUnavailable
		if provider != report.VendorUnknown {
			state = report.IdentityResolving
		}
		record := &inventoryRecord{
			device: attachment{
				descriptor: descriptor,
				report: report.DeviceReport{
					Attachment: attachmentInfo,
					Resolution: report.IdentityResolution{
						State:    state,
						Provider: provider,
					},
				},
			},
			resolveCtx: resolveCtx,
			cancel:     cancel,
			done:       make(chan struct{}),
		}
		next[id] = record
		if state == report.IdentityResolving {
			i.resolvers.Add(1)
			pending = append(pending, pendingIdentity{
				record:     record,
				id:         id,
				descriptor: descriptor,
			})
		} else {
			close(record.done)
		}
	}

	for id, record := range i.records {
		if next[id] == nil {
			record.cancel()
		}
	}
	i.records = next
	i.order = order
	i.mu.Unlock()

	for _, task := range pending {
		go i.resolveIdentity(task.record, task.id, task.descriptor)
	}
}

func (i *Inventory) resolveIdentity(
	record *inventoryRecord,
	id report.AttachmentID,
	descriptor discovery.Descriptor,
) {
	defer i.resolvers.Done()
	defer close(record.done)

	resolveCtx, cancel := context.WithTimeout(record.resolveCtx, identityTimeout)
	identity, provider, applicable, err := i.identity.Resolve(resolveCtx, descriptor)
	cancel()

	i.mu.Lock()
	current := i.records[id]
	if current != record || i.closed {
		i.mu.Unlock()
		return
	}

	resolution := report.IdentityResolution{Provider: provider}
	switch {
	case err != nil:
		resolution.State = report.IdentityFailed
		normalized := NormalizeError(err, failure.PhaseIdentity)
		resolution.Error = failure.Snapshot(normalized)
	case identity != nil:
		resolution.State = report.IdentityResolved
		current.device.report.Identity = identity
	case !applicable:
		resolution.State = report.IdentityUnavailable
	default:
		resolution.State = report.IdentityUnavailable
	}
	current.device.report.Resolution = resolution
	i.mu.Unlock()

	i.publish(InventoryTriggerIdentity, nil)
}

func (i *Inventory) runMonitor() {
	defer close(i.monitorDone)

	for {
		select {
		case <-i.ctx.Done():
			return
		case event, ok := <-i.monitor:
			if !ok {
				return
			}
			if event.Err != nil {
				normalized := NormalizeError(event.Err, failure.PhaseDiscovery)
				i.publish(InventoryTriggerTopology, failure.Snapshot(normalized))
				continue
			}

			timer := time.NewTimer(inventorySettleDelay)
			select {
			case <-i.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		if err := i.scan(i.ctx, InventoryTriggerTopology); err != nil {
			normalized := NormalizeError(err, failure.PhaseDiscovery)
			i.publish(InventoryTriggerTopology, failure.Snapshot(normalized))
		}
	}
}

func (i *Inventory) publish(trigger InventoryTrigger, failed *failure.Failure) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return
	}
	event := InventoryEvent{
		Trigger:  trigger,
		Snapshot: i.snapshotLocked(),
		Error:    failed,
	}

	select {
	case i.events <- event:
	default:
		select {
		case <-i.events:
		default:
		}
		i.events <- event
	}
}

func (i *Inventory) snapshotLocked() InventorySnapshot {
	devices := make([]report.DeviceReport, 0, len(i.order))
	for _, id := range i.order {
		if record := i.records[id]; record != nil {
			devices = append(devices, record.device.report)
		}
	}
	return InventorySnapshot{Devices: devices}
}
