package ctapkit

import (
	"context"
	"slices"
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

type inventoryRecord struct {
	device     attachment
	generation uint64
	resolveCtx context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	doneOnce   sync.Once
}

func (r *inventoryRecord) finish() {
	r.doneOnce.Do(func() {
		close(r.done)
	})
}

type resolveWork struct {
	record     *inventoryRecord
	generation uint64
}

// Inventory owns transport monitoring, attachment topology and optional
// identity resolution for one fixed transport mode.
type Inventory struct {
	mode        transport.Mode
	discovery   *discovery.Discovery
	identity    identityResolver
	open        authenticatorOpenFunc
	ctx         context.Context
	cancel      context.CancelFunc
	events      chan InventoryEvent
	monitor     <-chan discovery.Event
	workerDone  chan struct{}
	monitorDone chan struct{}
	closeOnce   sync.Once

	mu         sync.Mutex
	cond       *sync.Cond
	closed     bool
	generation uint64
	records    map[report.AttachmentID]*inventoryRecord
	order      []report.AttachmentID
	queue      []resolveWork
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
	inventory := &Inventory{
		mode:        mode,
		discovery:   discovery.New(),
		identity:    rtidentity.NewResolver(),
		open:        rtauthenticator.Open,
		ctx:         lifetime,
		cancel:      cancel,
		events:      make(chan InventoryEvent, 1),
		workerDone:  make(chan struct{}),
		monitorDone: make(chan struct{}),
		records:     make(map[report.AttachmentID]*inventoryRecord),
	}
	inventory.cond = sync.NewCond(&inventory.mu)

	monitor, err := inventory.discovery.Events(lifetime, mode)
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

	go inventory.runResolver()
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
	i.publish(InventoryTriggerManual, nil)

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
		i.promoteLocked(record)
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
		<-i.workerDone
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
		record.finish()
	}
	i.queue = nil
	i.cond.Broadcast()
	i.mu.Unlock()
	i.cancel()
}

func (i *Inventory) applyDescriptors(descriptors []discovery.Descriptor) {
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
			existing.finish()
		}

		i.generation++
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
			generation: i.generation,
			resolveCtx: resolveCtx,
			cancel:     cancel,
			done:       make(chan struct{}),
		}
		next[id] = record
		if state == report.IdentityResolving {
			i.queue = append(i.queue, resolveWork{
				record:     record,
				generation: record.generation,
			})
		} else {
			record.finish()
		}
	}

	for id, record := range i.records {
		if next[id] == nil {
			record.cancel()
			record.finish()
		}
	}
	i.records = next
	i.order = order
	i.cond.Broadcast()
	i.mu.Unlock()
}

func (i *Inventory) runResolver() {
	defer close(i.workerDone)

	for {
		i.mu.Lock()
		for !i.closed && len(i.queue) == 0 {
			i.cond.Wait()
		}
		if i.closed {
			i.mu.Unlock()
			return
		}
		work := i.queue[0]
		i.queue = i.queue[1:]
		current := i.records[work.record.device.report.Attachment.ID]
		if current != work.record ||
			current.generation != work.generation {
			i.mu.Unlock()
			work.record.finish()
			continue
		}
		descriptor := work.record.device.descriptor
		i.mu.Unlock()

		resolveCtx, cancel := context.WithTimeout(work.record.resolveCtx, identityTimeout)
		identity, provider, applicable, err := i.identity.Resolve(resolveCtx, descriptor)
		cancel()

		i.mu.Lock()
		current = i.records[work.record.device.report.Attachment.ID]
		if current == work.record &&
			current.generation == work.generation &&
			!i.closed {
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
		}
		work.record.finish()
		i.mu.Unlock()

		i.publish(InventoryTriggerIdentity, nil)
	}
}

func (i *Inventory) promoteLocked(record *inventoryRecord) {
	index := slices.IndexFunc(i.queue, func(work resolveWork) bool {
		return work.record == record
	})
	if index <= 0 {
		return
	}

	work := i.queue[index]
	copy(i.queue[1:index+1], i.queue[0:index])
	i.queue[0] = work
	i.cond.Signal()
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

		descriptors, err := i.discovery.Discover(i.ctx, i.mode)
		if err != nil {
			normalized := NormalizeError(err, failure.PhaseDiscovery)
			i.publish(InventoryTriggerTopology, failure.Snapshot(normalized))
			continue
		}
		i.applyDescriptors(descriptors)
		i.publish(InventoryTriggerTopology, nil)
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
