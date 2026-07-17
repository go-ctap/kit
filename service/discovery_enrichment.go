package service

import (
	"context"
	"time"

	"github.com/go-ctap/kit/internal/vendorinfo"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/report"
)

const enrichmentProbeTimeout = 2 * time.Second

type discoveryEnrichment struct {
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
	claims  map[string]chan struct{}
	cache   map[string]report.DeviceMetadata
}

func newDiscoveryEnrichment() discoveryEnrichment {
	return discoveryEnrichment{
		claims: make(map[string]chan struct{}),
		cache:  make(map[string]report.DeviceMetadata),
	}
}

func (s *Service) startEnrichment() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return
	}
	if s.enrichment.running {
		s.mu.Unlock()

		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.enrichment.running = true
	s.enrichment.cancel = cancel
	s.enrichment.done = make(chan struct{})
	s.mu.Unlock()

	go s.runEnrichment(ctx)
}

func (s *Service) runEnrichment(ctx context.Context) {
	attempted := make(map[string]struct{})
	for {
		device, ok := s.nextEnrichmentCandidate(ctx, attempted)
		if !ok {
			return
		}

		probeCtx, cancel := context.WithTimeout(ctx, enrichmentProbeTimeout)
		metadata, err := vendorinfo.Probe(probeCtx, device)
		cancel()
		if err == nil && metadata != nil {
			s.applyEnrichment(device, *metadata)
		}
		s.releaseDeviceClaim(device)
	}
}

func (s *Service) nextEnrichmentCandidate(
	ctx context.Context,
	attempted map[string]struct{},
) (report.DeviceReport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx.Err() != nil || s.closed {
		s.finishEnrichmentLocked()

		return report.DeviceReport{}, false
	}

	device, ok := takeEnrichmentCandidate(
		deviceReports(s.devices),
		s.enrichment.cache,
		attempted,
		s.deviceBusyForEnrichmentLocked,
	)
	if ok {
		s.enrichment.claims[enrichmentKey(device)] = make(chan struct{})

		return device, true
	}

	s.finishEnrichmentLocked()

	return report.DeviceReport{}, false
}

func (s *Service) releaseDeviceClaim(device report.DeviceReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := enrichmentKey(device)
	close(s.enrichment.claims[key])
	delete(s.enrichment.claims, key)
}

func takeEnrichmentCandidate(
	devices []report.DeviceReport,
	cache map[string]report.DeviceMetadata,
	attempted map[string]struct{},
	busy func(report.DeviceReport) bool,
) (report.DeviceReport, bool) {
	for _, device := range devices {
		if !vendorinfo.CanProbe(device) || busy(device) {
			continue
		}

		key := enrichmentKey(device)
		if _, ok := cache[key]; ok {
			continue
		}
		if _, ok := attempted[key]; ok {
			continue
		}

		attempted[key] = struct{}{}

		return device, true
	}

	return report.DeviceReport{}, false
}

func (s *Service) finishEnrichmentLocked() {
	if !s.enrichment.running {
		return
	}

	s.enrichment.running = false
	s.enrichment.cancel = nil
	close(s.enrichment.done)
	s.enrichment.done = nil
}

func (s *Service) applyEnrichment(device report.DeviceReport, metadata report.DeviceMetadata) {
	s.mu.Lock()
	if s.closed || s.hasSessionForDeviceLocked(device) ||
		!deviceReportPresent(deviceReports(s.devices), device) {
		s.mu.Unlock()

		return
	}

	s.enrichment.cache[enrichmentKey(device)] = cloneDeviceMetadata(metadata)
	snapshot := DiscoverySnapshot{Devices: s.deviceReportsWithMetadataLocked(s.devices)}
	s.mu.Unlock()

	s.emit(EventDiscoveryChanged, DiscoveryChangedEnvelope{
		Trigger:  DiscoveryTriggerEnriched,
		Snapshot: &snapshot,
	})
}

func (s *Service) claimDeviceForSession(
	ctx context.Context,
	device report.DeviceReport,
) (func(), error) {
	key := enrichmentKey(device)
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()

			return nil, closedServiceError(failure.PhaseSession)
		}
		current := s.enrichment.claims[key]
		if current == nil {
			s.enrichment.claims[key] = make(chan struct{})
			s.mu.Unlock()

			return func() {
				s.releaseDeviceClaim(device)
				s.startEnrichment()
			}, nil
		}
		s.mu.Unlock()

		select {
		case <-current:
		case <-ctx.Done():
			return nil, normalizeServicePhaseError(ctx.Err(), failure.PhaseSession)
		}
	}
}

func (s *Service) deviceBusyForEnrichmentLocked(device report.DeviceReport) bool {
	if s.enrichment.claims[enrichmentKey(device)] != nil {
		return true
	}

	return s.hasSessionForDeviceLocked(device)
}

func (s *Service) hasSessionForDeviceLocked(device report.DeviceReport) bool {
	for _, session := range s.sessions {
		if session.device.Transport == device.Transport && session.device.Fingerprint == device.Fingerprint {
			return true
		}
	}

	return false
}
