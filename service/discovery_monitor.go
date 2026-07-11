package service

import (
	"context"
	"errors"
	"time"

	ghid "github.com/go-ctap/hid"
)

const discoveryEventSettleTime = 100 * time.Millisecond

func (s *Service) StartDiscoveryMonitoring(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return closedServiceError()
	}
	if s.monitor != nil {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	receiver, err := s.openMonitor()
	if err != nil {
		return err
	}
	done := make(chan struct{})

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = receiver.Close()

		return closedServiceError()
	}
	if s.monitor != nil {
		s.mu.Unlock()
		_ = receiver.Close()

		return nil
	}
	s.monitor = receiver
	s.monitorDone = done
	go s.runDiscoveryMonitor(receiver, done)
	s.mu.Unlock()

	reconcileErr := s.reconcileTopology(ctx, s.currentDiscoverRequest(), DiscoveryTriggerMonitor, false)
	if reconcileErr != nil {
		s.mu.Lock()
		s.monitor = nil
		s.monitorDone = nil
		s.mu.Unlock()
		closeErr := receiver.Close()
		<-done

		return errors.Join(reconcileErr, closeErr)
	}

	return nil
}

func (s *Service) runDiscoveryMonitor(receiver ghid.EventReceiver, done chan<- struct{}) {
	defer close(done)

	events := receiver.Listen()
	var timer *time.Timer
	var timerC <-chan time.Time
	pending := false

	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	defer stopTimer()

	flush := func() {
		if !pending {
			return
		}

		pending = false
		_ = s.reconcileTopology(context.Background(), s.currentDiscoverRequest(), DiscoveryTriggerHotplug, false)
	}

	for {
		select {
		case hidEvent, ok := <-events:
			if !ok {
				return
			}
			if !isFIDOEvent(hidEvent) {
				continue
			}

			pending = true
			if timer == nil {
				timer = time.NewTimer(discoveryEventSettleTime)
			} else {
				stopTimer()
				timer.Reset(discoveryEventSettleTime)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			flush()
		}
	}
}

const (
	fidoUsagePage uint16 = 0xf1d0
	fidoUsage     uint16 = 0x01
)

func isFIDOEvent(event ghid.DeviceEvent) bool {
	if event.Type != ghid.DeviceEventConnected && event.Type != ghid.DeviceEventDisconnected {
		return false
	}

	if event.DeviceInfo == nil {
		return true
	}

	info := event.DeviceInfo
	if (info.UsagePage != 0 && info.UsagePage != fidoUsagePage) ||
		(info.Usage != 0 && info.Usage != fidoUsage) {
		return false
	}

	return true
}
