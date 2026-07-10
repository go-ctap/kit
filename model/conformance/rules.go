package conformance

var getInfoRules = func() []getInfoRule {
	rules := make([]getInfoRule, 0, 64)
	rules = append(rules, structuralRules()...)
	rules = append(rules, profileRules()...)
	rules = append(rules, featureRules()...)
	rules = append(rules, configRules()...)

	return rules
}()
