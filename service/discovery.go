package service

import (
	"context"
	"time"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model/failure"
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
		Error:    failure.Snapshot(result.err),
	}

	if force || result.changed || envelope.Error != nil {
		s.emit(EventDiscoveryChanged, envelope)
	}
	if result.snapshot != nil {
		s.startEnrichment()
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
		return result, normalizeServicePhaseError(err, failure.PhaseDiscovery)
	}

	if s.isClosed() {
		return result, closedServiceError(failure.PhaseDiscovery)
	}

	s.mu.Lock()
	previousDevices := append([]ctapkit.Device(nil), s.devices...)
	s.mu.Unlock()
	previousReports := s.deviceReportsWithMetadata(previousDevices)

	devices, scanErr := s.scanDevices(ctx, discoverOptions(req)...)
	if scanErr != nil && ctx.Err() != nil {
		return result, normalizeServicePhaseError(ctx.Err(), failure.PhaseDiscovery)
	}

	var nextReports []report.DeviceReport
	authoritative := scanErr == nil
	if authoritative {
		nextReports = s.deviceReportsWithMetadata(devices)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return result, closedServiceError(failure.PhaseDiscovery)
	}
	var affected []*managedSession
	if authoritative {
		s.pruneEnrichmentCacheLocked(devices)
		s.devices = devices
		s.lastDiscoverMode = normalizedDiscoverMode(req.Mode)
		affected = s.detachMissingSessionsLocked(nextReports)
	}
	s.mu.Unlock()

	closeErr := s.closeManagedSessions(affected)
	result.err = scanErr
	if result.err == nil {
		result.err = closeErr
	}
	if authoritative {
		snapshot := DiscoverySnapshot{Devices: nextReports}
		result.snapshot = &snapshot
		result.changed = !deviceReportsEqual(previousReports, nextReports)
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
		if err := session.session.Close(); err != nil && closeErr == nil {
			closeErr = err
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
		if device.Transport == selected.Transport && device.Fingerprint == selected.Fingerprint {
			return true
		}
	}

	return false
}

func closedServiceError(phase failure.Phase) error {
	return failure.New(failure.CodeServiceClosed,
		failure.WithPhase(phase),
	)
}
