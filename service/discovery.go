package service

import (
	"context"
	"errors"
	"slices"
	"time"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

func (s *Service) discoverSnapshot(ctx context.Context, req DiscoverRequest) (DiscoverySnapshot, error) {
	result, err := s.updateDiscovery(ctx, req)
	if err != nil {
		return DiscoverySnapshot{}, err
	}
	if result.snapshot == nil {
		return DiscoverySnapshot{}, result.err
	}

	return *result.snapshot, result.err
}

func (s *Service) RefreshDiscovery(ctx context.Context, req DiscoverRequest) error {
	return s.reconcileTopology(ctx, s.effectiveDiscoverRequest(req), DiscoveryTriggerManual, true)
}

func (s *Service) reconcileTopology(
	ctx context.Context,
	req DiscoverRequest,
	trigger DiscoveryTrigger,
	force bool,
) error {
	result, err := s.updateDiscovery(ctx, req)
	if err != nil {
		return err
	}

	envelope := DiscoveryChangedEnvelope{
		Trigger:  trigger,
		Snapshot: result.snapshot,
		Error:    runtimeErrorEnvelope(result.err),
	}

	if force || result.changed || envelope.Error != nil {
		s.emit(EventDiscoveryChanged, envelope)
	}

	return nil
}

type discoveryResult struct {
	snapshot *DiscoverySnapshot
	err      error
	changed  bool
}

func (s *Service) updateDiscovery(
	ctx context.Context,
	req DiscoverRequest,
) (discoveryResult, error) {
	result := discoveryResult{}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	if s.isClosed() {
		return result, closedServiceError()
	}

	s.mu.Lock()
	previousDevices := append([]ctapkit.Device(nil), s.devices...)
	s.mu.Unlock()
	previousReports := deviceReports(previousDevices)

	devices, scanErr := s.scanDevices(ctx, discoverOptions(req)...)
	if scanErr != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}

	var nextReports []report.DeviceReport
	authoritative := scanErr == nil
	if authoritative {
		nextReports = deviceReports(devices)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return result, closedServiceError()
	}
	var affected []*managedSession
	if authoritative {
		s.devices = devices
		s.lastDiscoverMode = normalizedDiscoverMode(req.Mode)
		affected = s.detachMissingSessionsLocked(nextReports)
	}
	s.mu.Unlock()

	closeErr := s.closeManagedSessions(affected)
	result.err = errors.Join(scanErr, closeErr)
	if authoritative {
		snapshot := DiscoverySnapshot{Devices: nextReports}
		result.snapshot = &snapshot
		result.changed = !slices.Equal(previousReports, nextReports)
	}

	return result, nil
}

func (s *Service) detachMissingSessionsLocked(devices []report.DeviceReport) []*managedSession {
	affected := make([]*managedSession, 0)
	for id, session := range s.sessions {
		if deviceReportPresent(devices, session.device) {
			continue
		}

		affected = append(affected, session)
		delete(s.sessions, id)
	}

	return affected
}

func (s *Service) closeManagedSessions(sessions []*managedSession) error {
	var closeErr error
	for _, session := range sessions {
		s.cancelSessionOperations(session.id)
		if err := session.session.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		session.updatedAt = time.Now().UTC()
		s.waitForSessionOperations(session.id)
	}

	return closeErr
}

func (s *Service) waitForSessionOperations(id SessionID) {
	for {
		s.mu.Lock()
		operations := make([]*operationState, 0, 1)
		for _, operation := range s.operations {
			if operation.sessionID == id {
				operations = append(operations, operation)
			}
		}
		s.mu.Unlock()

		if len(operations) == 0 {
			return
		}
		for _, operation := range operations {
			operation.cancel()
			<-operation.done
		}
	}
}

func (s *Service) currentDiscoverRequest() DiscoverRequest {
	s.mu.Lock()
	mode := s.lastDiscoverMode
	s.mu.Unlock()

	return DiscoverRequest{Mode: mode}
}

func (s *Service) effectiveDiscoverRequest(req DiscoverRequest) DiscoverRequest {
	if req.Mode == "" {
		return s.currentDiscoverRequest()
	}

	return req
}

func (s *Service) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()

	return closed
}

func normalizedDiscoverMode(mode transport.Mode) transport.Mode {
	if mode == "" {
		return transport.ModeAuto
	}

	return mode
}

func deviceReportPresent(devices []report.DeviceReport, selected report.DeviceReport) bool {
	for _, device := range devices {
		if device.Transport == selected.Transport && device.DeviceID == selected.DeviceID {
			return true
		}
	}

	return false
}

func closedServiceError() error {
	return model.NewRuntimeError(model.ErrorInvalidState, "service is closed", nil)
}
