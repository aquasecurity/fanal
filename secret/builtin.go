package secret

import (
	"regexp"

	"github.com/aquasecurity/fanal/types"
)

var (
	RuleTypeAWS    = types.SecretRuleType("AWS")
	RuleTypeGitHub = types.SecretRuleType("GitHub")
)

var builtinRules = []Rule{
	{
		ID:       "aws-access-key-id",
		Type:     RuleTypeAWS,
		Severity: "CRITICAL",
		Title:    "AWS Access Key ID",
		Regex:    regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	},
	{
		ID:       "github-pat",
		Type:     RuleTypeGitHub,
		Title:    "GitHub Personal Access Token",
		Severity: "CRITICAL",
		Regex:    regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	},
	{
		ID:       "github-oauth",
		Type:     RuleTypeGitHub,
		Title:    "GitHub OAuth Access Token",
		Severity: "CRITICAL",
		Regex:    regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
	},
}
