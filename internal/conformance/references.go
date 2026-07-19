package conformance

import model "github.com/go-ctap/kit/model/conformance"

const (
	ctap20URL = "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html"
	ctap21URL = "https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html"
	ctap23URL = "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html"
)

func requirement(specification model.SpecificationID, section, clause, url string, level model.RequirementLevel) model.RequirementRef {
	return model.RequirementRef{
		ID:            model.RequirementID(string(specification) + ":" + section + ":" + clause),
		Specification: specification,
		Section:       section,
		Clause:        clause,
		URL:           url,
		Level:         level,
	}
}

func getInfoRequirement(target model.Target, clause string, level model.RequirementLevel) model.RequirementRef {
	switch target.Specification {
	case model.SpecificationCTAP20:
		return requirement(model.SpecificationCTAP20, "5.4", clause, ctap20URL+"#authenticatorGetInfo", level)
	case model.SpecificationCTAP21:
		return requirement(model.SpecificationCTAP21, "6.4", clause, ctap21URL+"#authenticatorGetInfo", level)
	case model.SpecificationCTAP23:
		return requirement(model.SpecificationCTAP23, "6.4", clause, ctap23URL+"#authenticatorGetInfo", level)
	default:
		return model.RequirementRef{}
	}
}

func mandatoryRequirement(target model.Target, item, clause string) model.RequirementRef {
	switch target.Specification {
	case model.SpecificationCTAP21:
		return requirement(model.SpecificationCTAP21, "9", "item-"+item+"-"+clause, ctap21URL+"#mandatory-features", model.RequirementMust)
	case model.SpecificationCTAP23:
		return requirement(model.SpecificationCTAP23, "9", "item-"+item+"-"+clause, ctap23URL+"#mandatory-features", model.RequirementMust)
	default:
		return model.RequirementRef{}
	}
}

func configRequirement(section, clause, anchor string, level model.RequirementLevel) model.RequirementRef {
	return requirement(model.SpecificationCTAP23, section, clause, ctap23URL+anchor, level)
}

func featureRequirement(target model.Target, section, clause, anchor string, level model.RequirementLevel) model.RequirementRef {
	switch target.Specification {
	case model.SpecificationCTAP21:
		return requirement(model.SpecificationCTAP21, section, clause, ctap21URL+anchor, level)
	case model.SpecificationCTAP23:
		return requirement(model.SpecificationCTAP23, section, clause, ctap23URL+anchor, level)
	default:
		return model.RequirementRef{}
	}
}
