package conformance

const (
	ctap20URL = "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html"
	ctap21URL = "https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html"
	ctap23URL = "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html"
)

func requirement(specification SpecificationID, section, clause, url string, level RequirementLevel) RequirementRef {
	return RequirementRef{
		ID:            RequirementID(string(specification) + ":" + section + ":" + clause),
		Specification: specification,
		Section:       section,
		Clause:        clause,
		URL:           url,
		Level:         level,
	}
}

func getInfoRequirement(target Target, clause string, level RequirementLevel) RequirementRef {
	switch target.Specification {
	case SpecificationCTAP20:
		return requirement(SpecificationCTAP20, "5.4", clause, ctap20URL+"#authenticatorGetInfo", level)
	case SpecificationCTAP21:
		return requirement(SpecificationCTAP21, "6.4", clause, ctap21URL+"#authenticatorGetInfo", level)
	case SpecificationCTAP23:
		return requirement(SpecificationCTAP23, "6.4", clause, ctap23URL+"#authenticatorGetInfo", level)
	default:
		return RequirementRef{}
	}
}

func mandatoryRequirement(target Target, item, clause string) RequirementRef {
	switch target.Specification {
	case SpecificationCTAP21:
		return requirement(SpecificationCTAP21, "9", "item-"+item+"-"+clause, ctap21URL+"#mandatory-features", RequirementMust)
	case SpecificationCTAP23:
		return requirement(SpecificationCTAP23, "9", "item-"+item+"-"+clause, ctap23URL+"#mandatory-features", RequirementMust)
	default:
		return RequirementRef{}
	}
}

func configRequirement(section, clause, anchor string, level RequirementLevel) RequirementRef {
	return requirement(SpecificationCTAP23, section, clause, ctap23URL+anchor, level)
}

func featureRequirement(target Target, section, clause, anchor string, level RequirementLevel) RequirementRef {
	switch target.Specification {
	case SpecificationCTAP21:
		return requirement(SpecificationCTAP21, section, clause, ctap21URL+anchor, level)
	case SpecificationCTAP23:
		return requirement(SpecificationCTAP23, section, clause, ctap23URL+anchor, level)
	default:
		return RequirementRef{}
	}
}
