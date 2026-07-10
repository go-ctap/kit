package conformance

func featureRules() []getInfoRule {
	rules := make([]getInfoRule, 0, 32)
	rules = append(rules, blobRules()...)
	rules = append(rules, pinRules()...)
	rules = append(rules, optionDependencyRules()...)

	return rules
}
