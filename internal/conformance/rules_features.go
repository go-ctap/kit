package conformance

import "slices"

func featureRules() []getInfoRule {
	return slices.Concat(blobRules(), pinRules(), optionDependencyRules())
}
