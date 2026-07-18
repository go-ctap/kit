package conformance

import "github.com/go-ctap/ctap/protocol"

func resolveTarget(versions protocol.Versions) (Target, bool) {
	if versions.Supports(protocol.FIDO_2_3) {
		return Target{Specification: SpecificationCTAP23, Profile: ProfileFIDO23}, true
	}

	if versions.Supports(protocol.FIDO_2_1) {
		return Target{Specification: SpecificationCTAP21, Profile: ProfileFIDO21}, true
	}

	if versions.Supports(protocol.FIDO_2_0) {
		return Target{Specification: SpecificationCTAP20, Profile: ProfileFIDO20}, true
	}

	return Target{}, false
}

func advertisedProfiles(versions protocol.Versions) []Profile {
	profiles := make([]Profile, 0, 5)
	if versions.Supports(protocol.U2F_V2) {
		profiles = append(profiles, ProfileU2FV2)
	}

	if versions.Supports(protocol.FIDO_2_0) {
		profiles = append(profiles, ProfileFIDO20)
	}

	if versions.Supports(protocol.FIDO_2_1_PRE) {
		profiles = append(profiles, ProfileFIDO21Pre)
	}

	if versions.Supports(protocol.FIDO_2_1) {
		profiles = append(profiles, ProfileFIDO21)
	}

	if versions.Supports(protocol.FIDO_2_3) {
		profiles = append(profiles, ProfileFIDO23)
	}

	return profiles
}

func isCanonicalTarget(target Target) bool {
	switch target {
	case Target{Specification: SpecificationCTAP20, Profile: ProfileFIDO20},
		Target{Specification: SpecificationCTAP21, Profile: ProfileFIDO21},
		Target{Specification: SpecificationCTAP23, Profile: ProfileFIDO23}:
		return true
	default:
		return false
	}
}
