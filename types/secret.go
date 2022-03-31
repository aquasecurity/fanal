package types

type SecretRuleType string

type Secret struct {
	FilePath string
	Findings []SecretFinding
	Layer    Layer `json:",omitempty"`
}

type SecretFinding struct {
	RuleID    string
	Type      SecretRuleType
	Severity  string
	Title     string
	StartLine int
	EndLine   int
	Match     string
}
