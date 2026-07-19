package conformance

import (
	"github.com/go-ctap/ctap/protocol"
	model "github.com/go-ctap/kit/model/conformance"
)

func resolveTarget(versions protocol.Versions) (model.Target, bool) {
	if versions.Supports(protocol.FIDO_2_3) {
		return model.Target{Specification: model.SpecificationCTAP23, Profile: model.ProfileFIDO23}, true
	}

	if versions.Supports(protocol.FIDO_2_1) {
		return model.Target{Specification: model.SpecificationCTAP21, Profile: model.ProfileFIDO21}, true
	}

	if versions.Supports(protocol.FIDO_2_0) {
		return model.Target{Specification: model.SpecificationCTAP20, Profile: model.ProfileFIDO20}, true
	}

	return model.Target{}, false
}

func advertisedProfiles(versions protocol.Versions) []model.Profile {
	profiles := make([]model.Profile, 0, 5)
	if versions.Supports(protocol.U2F_V2) {
		profiles = append(profiles, model.ProfileU2FV2)
	}

	if versions.Supports(protocol.FIDO_2_0) {
		profiles = append(profiles, model.ProfileFIDO20)
	}

	if versions.Supports(protocol.FIDO_2_1_PRE) {
		profiles = append(profiles, model.ProfileFIDO21Pre)
	}

	if versions.Supports(protocol.FIDO_2_1) {
		profiles = append(profiles, model.ProfileFIDO21)
	}

	if versions.Supports(protocol.FIDO_2_3) {
		profiles = append(profiles, model.ProfileFIDO23)
	}

	return profiles
}

func isCanonicalTarget(target model.Target) bool {
	switch target {
	case model.Target{Specification: model.SpecificationCTAP20, Profile: model.ProfileFIDO20},
		model.Target{Specification: model.SpecificationCTAP21, Profile: model.ProfileFIDO21},
		model.Target{Specification: model.SpecificationCTAP23, Profile: model.ProfileFIDO23}:
		return true
	default:
		return false
	}
}
