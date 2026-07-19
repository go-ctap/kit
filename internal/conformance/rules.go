package conformance

import "slices"

var getInfoRules = func() []getInfoRule {
	return slices.Concat(structuralRules(), profileRules(), featureRules(), configRules())
}()
