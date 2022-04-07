package secret

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	Rules         []Rule
	AllowList     AllowList
	ExcludeBlocks ExcludeBlocks
}
type Rule struct {
	ID            string
	Type          types.SecretRuleType
	Severity      string
	Title         string
	Regex         *regexp.Regexp
	Path          *regexp.Regexp
	AllowList     AllowList
	ExcludeBlocks ExcludeBlocks
}

type RuleResult struct {
	RuleID        string
	Type          types.SecretRuleType
	Severity      string
	Title         string
	StartPosition int
	EndPosition   int
	Match         string
}

type AllowList struct {
	Title   string
	Regexes []*regexp.Regexp
	Paths   []*regexp.Regexp
}

type ExcludeBlocks struct {
	Title   string
	Regexes []*regexp.Regexp
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
	var allRulesResults []RuleResult

	if isMatchingString(args.FilePath, s.AllowList.Paths) {
		return types.Secret{}
	}

	for _, rule := range s.Rules {
		var ruleResults []RuleResult
		// Check if the file path should be scanned by this rule
		if rule.Path != nil && !rule.Path.MatchString(args.FilePath) {
			continue
		}

		if isMatchingString(args.FilePath, rule.AllowList.Paths) {
			continue
		}

		// Detect secrets
		optionalLocations := rule.Regex.FindAllIndex(args.Content, -1)
		if len(optionalLocations) == 0 {
			continue
		}

		// Parse to result and skip if the result is allowed
		for _, loc := range optionalLocations {
			result := RuleResult{
				RuleID:        rule.ID,
				Type:          rule.Type,
				Severity:      strings.ToUpper(rule.Severity),
				Title:         rule.Title,
				StartPosition: loc[0],
				EndPosition:   loc[1],
				Match:         string(args.Content[loc[0]:loc[1]]),
			}
			if !isMatchingString(result.Match, append(rule.AllowList.Regexes, s.AllowList.Regexes...)) {
				ruleResults = append(ruleResults, result)
			}
		}

		// Find rule excluded blocks
		var allowedBlocksLocations [][]int
		for _, regex := range rule.ExcludeBlocks.Regexes {
			allowedBlocksLocations = append(allowedBlocksLocations, regex.FindAllIndex(args.Content, -1)...)
		}

		// Remove results that are in allowed blocks
		ruleResults = removeAllowedSecrets(ruleResults, allowedBlocksLocations)

		allRulesResults = append(allRulesResults, ruleResults...)
	}

	// Find global excluded blocks
	if len(allRulesResults) > 0 && len(s.ExcludeBlocks.Regexes) > 0 {
		globalAllowedBlocksLocations := make([][]int, 0)
		for _, regex := range s.ExcludeBlocks.Regexes {
			globalAllowedBlocksLocations = append(globalAllowedBlocksLocations, regex.FindAllIndex(args.Content, -1)...)
		}

		// Filter out allowed results
		allRulesResults = removeAllowedSecrets(allRulesResults, globalAllowedBlocksLocations)
	}

	// Parse to findings
	for _, result := range allRulesResults {
		startLine, endLine, matchLine := findLocation(result.StartPosition, result.EndPosition, args.Content)
		findings = append(findings, types.SecretFinding{
			RuleID:    result.RuleID,
			Type:      result.Type,
			Severity:  result.Severity,
			Title:     result.Title,
			StartLine: startLine,
			EndLine:   endLine,
			Match:     matchLine,
		})
	}

	return types.Secret{
		FilePath: args.FilePath,
		Findings: findings,
	}
}

func isMatchingString(content string, regexes []*regexp.Regexp) bool {
	for _, regex := range regexes {
		if regex.MatchString(content) {
			return true
		}
	}
	return false
}

func removeAllowedSecrets(allRuleResults []RuleResult, allowedLocations [][]int) []RuleResult {
	if len(allowedLocations) == 0 {
		return allRuleResults
	}

	results := make([]RuleResult, 0)
	for _, result := range allRuleResults {
		if !isResultAllowed(result, allowedLocations) {
			results = append(results, result)
		}
	}
	return results
}

func isResultAllowed(result RuleResult, allowedLocations [][]int) bool {
	for _, allowedLocation := range allowedLocations {
		if result.StartPosition >= allowedLocation[0] && result.EndPosition <= allowedLocation[1] {
			return true
		}
	}
	return false
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
