package service

import (
	"slices"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
)

func (s *Service) deviceReportsWithMetadata(devices []ctapkit.Device) []report.DeviceReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.deviceReportsWithMetadataLocked(devices)
}

func (s *Service) deviceReportsWithMetadataLocked(devices []ctapkit.Device) []report.DeviceReport {
	reports := deviceReports(devices)
	for index := range reports {
		if cached, ok := s.enrichment.cache[enrichmentKey(reports[index])]; ok {
			metadata := cloneDeviceMetadata(cached)
			reports[index].Metadata = &metadata
		}
	}

	return reports
}

func (s *Service) reportWithMetadata(device report.DeviceReport) report.DeviceReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cached, ok := s.enrichment.cache[enrichmentKey(device)]; ok {
		metadata := cloneDeviceMetadata(cached)
		device.Metadata = &metadata
	}

	return device
}

func (s *Service) mergeInspectMetadata(selectionID SelectionID, result *model.InspectOutput) *DiscoverySnapshot {
	if result == nil {
		return nil
	}

	s.mu.Lock()
	selected := s.selected
	if selected == nil || selected.id != selectionID {
		s.mu.Unlock()

		return nil
	}

	key := enrichmentKey(selected.device)
	cached, cachedOK := s.enrichment.cache[key]
	if result.Result.Device.Metadata == nil {
		if cachedOK {
			metadata := cloneDeviceMetadata(cached)
			result.Result.Device.Metadata = &metadata
		}
		s.mu.Unlock()

		return nil
	}

	metadata := cloneDeviceMetadata(*result.Result.Device.Metadata)
	fingerprint := selected.device.Fingerprint
	changed := !cachedOK || !deviceMetadataEqual(cached, metadata)
	s.enrichment.cache[key] = metadata

	selectionMetadata := cloneDeviceMetadata(metadata)
	selected.device.Metadata = &selectionMetadata
	resultMetadata := cloneDeviceMetadata(metadata)
	result.Result.Device.Metadata = &resultMetadata
	var snapshot *DiscoverySnapshot
	if changed {
		snapshot = &DiscoverySnapshot{Devices: s.deviceReportsWithMetadataLocked(s.devices)}
	}
	s.mu.Unlock()

	s.persistDeviceMetadata(fingerprint, metadata)
	return snapshot
}

func (s *Service) pruneEnrichmentCacheLocked(devices []ctapkit.Device) {
	present := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		present[enrichmentKey(device.Report())] = struct{}{}
	}
	for key := range s.enrichment.cache {
		if _, ok := present[key]; !ok {
			delete(s.enrichment.cache, key)
		}
	}
}

func enrichmentKey(device report.DeviceReport) string {
	return string(device.Transport) + "\x00" + device.Fingerprint
}

func cloneDeviceMetadata(metadata report.DeviceMetadata) report.DeviceMetadata {
	clone := metadata
	clone.Interfaces = make([]report.InterfaceReport, len(metadata.Interfaces))
	for index, interfaceReport := range metadata.Interfaces {
		clone.Interfaces[index] = interfaceReport
		clone.Interfaces[index].Supported = append([]report.Capability(nil), interfaceReport.Supported...)
		clone.Interfaces[index].Enabled = append([]report.Capability(nil), interfaceReport.Enabled...)
	}

	return clone
}

func deviceReportsEqual(first, second []report.DeviceReport) bool {
	return slices.EqualFunc(first, second, func(left, right report.DeviceReport) bool {
		leftMetadata := left.Metadata
		rightMetadata := right.Metadata
		left.Metadata = nil
		right.Metadata = nil

		if left != right {
			return false
		}
		if leftMetadata == nil || rightMetadata == nil {
			return leftMetadata == rightMetadata
		}

		return deviceMetadataEqual(*leftMetadata, *rightMetadata)
	})
}

func deviceMetadataEqual(first, second report.DeviceMetadata) bool {
	if first.Model != second.Model || first.Serial != second.Serial || first.Firmware != second.Firmware {
		return false
	}

	return slices.EqualFunc(first.Interfaces, second.Interfaces, func(left, right report.InterfaceReport) bool {
		return left.Interface == right.Interface &&
			slices.Equal(left.Supported, right.Supported) &&
			slices.Equal(left.Enabled, right.Enabled)
	})
}
