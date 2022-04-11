package secret

import (
	"github.com/aquasecurity/fanal/types"
)

var (
	CategoryAWS     = types.SecretRuleCategory("AWS")
	CategoryGitHub  = types.SecretRuleCategory("GitHub")
	CategoryGeneric = types.SecretRuleCategory("Generic")
)

var builtinRules = []Rule{
	{
		ID:       "aws-access-key-id",
		Category: CategoryAWS,
		Severity: "CRITICAL",
		Title:    "AWS Access Key ID",
		Regex:    MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	},
	{
		ID:       "github-pat",
		Category: CategoryGitHub,
		Title:    "GitHub Personal Access Token",
		Severity: "CRITICAL",
		Regex:    MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	},
	{
		ID:       "github-oauth",
		Category: CategoryGitHub,
		Title:    "GitHub OAuth Access Token",
		Severity: "CRITICAL",
		Regex:    MustCompile(`gho_[0-9a-zA-Z]{36}`),
	},
}
