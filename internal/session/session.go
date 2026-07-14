package session

import (
	"context"
	"errors"
	"sync"

	"github.com/go-ctap/kit/internal/authenticator"
	"github.com/go-ctap/kit/internal/device"
	rtruntime "github.com/go-ctap/kit/internal/runtime"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
)

type Core struct {
	lease             *device.Lease
	selected          report.DeviceReport
	device            authenticator.Device
	events            *rtruntime.EventDispatcher
	strictPermissions bool

	workflowMu sync.Mutex
	stateMu    sync.Mutex
	closed     bool

	activeCancel context.CancelFunc
	closeOnce    sync.Once
	closeErr     error
	cache        Cache
}

func New(
	lease *device.Lease,
	selected report.DeviceReport,
	device authenticator.Device,
	events model.EventSink,
	strictPermissions bool,
) *Core {
	if events == nil {
		events = model.NoopEventSink{}
	}

	return &Core{
		lease:             lease,
		selected:          selected,
		device:            device,
		events:            rtruntime.NewEventDispatcher(events),
		strictPermissions: strictPermissions,
		cache:             NewCache(),
	}
}

func (c *Core) Info() model.SessionInfo {
	c.stateMu.Lock()
	closed := c.closed
	c.stateMu.Unlock()

	return model.SessionInfo{
		Device: c.SelectedDevice(),
		Closed: closed,
	}
}

func (c *Core) SelectedDevice() report.DeviceReport {
	return c.selected
}

func (c *Core) Authenticator() authenticator.Device {
	return c.device
}

func (c *Core) EventSink() model.EventSink {
	if c.events == nil {
		return model.NoopEventSink{}
	}

	return c.events
}

func (c *Core) StrictPermissions() bool {
	return c.strictPermissions
}

func (c *Core) Cache() *Cache {
	return &c.cache
}

func (c *Core) InteractionBroker(handler model.InteractionHandler) *rtruntime.InteractionBroker {
	return rtruntime.NewInteractionBroker(c.EventSink(), handler)
}

func (c *Core) TokenService(
	interactions *rtruntime.InteractionBroker,
	verificationFlow model.VerificationFlow,
) *rtruntime.TokenService {
	return rtruntime.NewTokenService(
		c.Cache(),
		interactions,
		verificationFlow,
	)
}

func (c *Core) Close() error {
	c.markClosedAndCancelActive()

	c.closeOnce.Do(func() {
		c.workflowMu.Lock()
		defer c.workflowMu.Unlock()

		c.invalidateSessionState()

		var authenticatorErr error
		if c.device != nil {
			authenticatorErr = c.Authenticator().Close()
		}

		var leaseErr error
		if c.lease != nil {
			leaseErr = c.lease.Close()
		}

		c.closeErr = errors.Join(authenticatorErr, leaseErr)
	})

	return c.closeErr
}

func (c *Core) markClosedAndCancelActive() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	if c.closed {
		return
	}

	c.closed = true
	if c.activeCancel != nil {
		c.activeCancel()
	}
}

func (c *Core) trackActiveOperation(cancel context.CancelFunc) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	if c.closed {
		return failure.New(failure.CodeSessionClosed,
			failure.WithPhase(failure.PhaseSession),
		)
	}

	c.activeCancel = cancel

	return nil
}

func (c *Core) clearActiveOperation() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	c.activeCancel = nil
}

func (c *Core) invalidateSessionState() {
	c.Cache().InvalidateAll()
}
