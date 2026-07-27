package conformance

import "slices"

var getInfoRules = func() []getInfoRule {
	return slices.Concat(
		structuralRules(),
		profileRules(),
		blobRules(),
		pinRules(),
		optionDependencyRules(),
		configRules(),
	)
}()
