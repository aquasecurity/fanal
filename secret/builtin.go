package secret

import (
	"regexp"

	"github.com/aquasecurity/fanal/types"
)

var (
	RuleTypeAWS           = types.SecretRuleType("AWS")
	RuleTypeGitHub        = types.SecretRuleType("GitHub")
	RuleTypeGenericSecret = types.SecretRuleType("GenericSecret")
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
	{
		ID:       "generic-secret",
		Type:     RuleTypeGenericSecret,
		Title:    "Generic Secret",
		Severity: "HIGH",
		Regex:    regexp.MustCompile(`(?i)(?:dbpasswd|dbhost|token|secret|password|pwd)\w*["']?\]?\s*[=:]\s*['"]([\w@0-9a-zA-Z-_\/+!{}\/=. ]{5,160})['"]`),
		AllowList: AllowList{
			Title: "False positives",
			Paths: []*regexp.Regexp{regexp.MustCompile(`(.*?)(\.env|gradle\.properties)$`)},
			Regexes: []*regexp.Regexp{
				regexp.MustCompile(`(?i)\w*(?:prefix|suffix|default|field|key)\w*\s*[=:]`),
				regexp.MustCompile(`(?i)\w*(prefix|suffix|field|default|key|$\{.*?\})\w*[\]"']*\s+[=:]`),
				regexp.MustCompile(`(?i)=[\s*\w\S]*[\[\(][[\s\S\w]*[\]\)]`),
				regexp.MustCompile(`(?i)=\s*(\w*[\.\/]\w*)+`),
				regexp.MustCompile(`(?i)[=:]\s*['"](\w*[\.\/]\w*)+['"]`),
				regexp.MustCompile(`(?i)[=:]\s*\S*(sample|example|false|true|some)`),
				regexp.MustCompile(`(?i)ENC[[]`),
				regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
				regexp.MustCompile(`(?i)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]`),
				regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
				regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
				regexp.MustCompile(`[:=]\s*\w*?(\.\w*)+`),
				regexp.MustCompile(`[:=]\s*\w*?([\[\(]['"]?\w*['"]?[\]\)])+`),
				regexp.MustCompile(`(?i)^\s*\[.*\]\s*[=:]`),
			},
		},
	},
}
