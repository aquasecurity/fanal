package secret

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	Rules     []Rule
	AllowList AllowList
}

type Rule struct {
	ID        string
	Type      types.SecretRuleType
	Severity  string
	Title     string
	Regex     *regexp.Regexp
	Path      *regexp.Regexp
	AllowList AllowList
}

type AllowList struct {
	Title   string
	Regexes []*regexp.Regexp
	Paths   []*regexp.Regexp
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

	for _, path := range s.AllowList.Paths {
		if path.MatchString(args.FilePath) {
			return types.Secret{}
		}
	}

	for _, rule := range s.Rules {
		// Check if the file path should be scanned by this rule
		if rule.Path != nil && !rule.Path.MatchString(args.FilePath) {
			continue
		}

		skipRule := false
		for _, path := range rule.AllowList.Paths {
			if path.MatchString(args.FilePath) {
				skipRule = true
				break
			}
		}
		if skipRule {
			continue
		}

		// Detect secrets
		optionalLocations := rule.Regex.FindAllIndex(args.Content, -1)
		if len(optionalLocations) == 0 {
			continue
		}

		// Find allowed locations
		allowedLocations := make([][]int, 0)
		if len(s.AllowList.Regexes) > 0 {
			rule.AllowList.Regexes = append(rule.AllowList.Regexes, s.AllowList.Regexes...)
		}
		for _, regex := range rule.AllowList.Regexes {
			allowedLocations = append(allowedLocations, regex.FindAllIndex(args.Content, -1)...)
		}

		locations := make([][]int, 0)
		// Find locations that are not in allowed locations
		if len(allowedLocations) > 0 {
			for _, currLocation := range optionalLocations {
				found := false
				if currLocation[1] < allowedLocations[0][0] {
					locations = append(locations, currLocation)
					continue
				}
				for _, allowedLocation := range allowedLocations {
					if allowedLocation[0] > currLocation[1] {
						break
					}
					if currLocation[0] >= allowedLocation[0] && currLocation[1] <= allowedLocation[1] {
						found = true
						break
					}
				}
				if !found {
					locations = append(locations, currLocation)
				}
			}
		} else {
			locations = optionalLocations
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
