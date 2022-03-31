package secret

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	Rules []Rule
}

type Rule struct {
	ID       string
	Type     types.SecretRuleType
	Severity string
	Title    string
	Regex    *regexp.Regexp
	Path     *regexp.Regexp
}

func NewScanner(rulePath string) Scanner {
	if rulePath != "" {
		// TODO: Load custom rules here
	}
	return Scanner{
		Rules: builtinRules, // TODO: Merge built-in rules and custom rules here
	}
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func (s Scanner) Scan(args ScanArgs) types.Secret {
	var findings []types.SecretFinding
	for _, rule := range s.Rules {
		// Check if the file path should be scanned by this rule
		if rule.Path != nil && !rule.Path.MatchString(args.FilePath) {
			continue
		}

		// Detect secrets
		locations := rule.Regex.FindAllIndex(args.Content, -1)
		if len(locations) == 0 {
			continue
		}

		for _, loc := range locations {
			start, end := loc[0], loc[1]
			startLine, endLine, match := findLocation(start, end, args.Content)
			findings = append(findings, types.SecretFinding{
				RuleID:    rule.ID,
				Type:      rule.Type,
				Severity:  strings.ToUpper(rule.Severity),
				Title:     rule.Title,
				StartLine: startLine,
				EndLine:   endLine,
				Match:     match,
			})
		}
	}

	return types.Secret{
		FilePath: args.FilePath,
		Findings: findings,
	}
}

func findLocation(start, end int, content []byte) (int, int, string) {
	startLineNum := bytes.Count(content[:start], lineSep) + 1
	endLineNum := startLineNum + 1 // TODO: support multi lines

	lineStart := bytes.LastIndex(content[:start], lineSep)
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart += 1
	}

	lineEnd := bytes.Index(content[start:], lineSep)
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}

	match := string(content[start:end])
	matchLine := string(content[lineStart:lineEnd])

	// Mask credentials
	matchLine = strings.ReplaceAll(matchLine, match, "*****")

	return startLineNum, endLineNum, matchLine
}
