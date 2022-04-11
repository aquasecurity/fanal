package secret

import (
	"bytes"
	"regexp"
	"strings"
	"sync"

	"github.com/aquasecurity/fanal/types"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	Rules        []Rule
	AllowRule    AllowRule
	ExcludeBlock ExcludeBlock
}
type Rule struct {
	ID           string
	Type         types.SecretRuleType
	Severity     string
	Title        string
	Regex        *regexp.Regexp
	Path         *regexp.Regexp
	AllowRule    AllowRule
	ExcludeBlock ExcludeBlock
}

func (r Rule) MatchPath(path string) bool {
	if r.Path == nil {
		return true
	}
	return matchString(path, r.Path)
}

func (r Rule) AllowPath(path string) bool {
	return r.AllowRule.AllowPath(path)
}

func (r Rule) Allow(match string) bool {
	return r.AllowRule.Allow(match)
}

type AllowRule struct {
	Title   string
	Regexes []*regexp.Regexp
	Paths   []*regexp.Regexp
}

func (a AllowRule) AllowPath(path string) bool {
	return matchString(path, a.Paths...)
}

func (a AllowRule) Allow(match string) bool {
	return matchString(match, a.Regexes...)
}

func matchString(s string, regexps ...*regexp.Regexp) bool {
	for _, r := range regexps {
		if r != nil && r.MatchString(s) {
			return true
		}
	}
	return false
}

type ExcludeBlock struct {
	Title   string
	Regexes []*regexp.Regexp
}

type Location struct {
	Start int
	End   int
}

func newLocation(start, end int) Location {
	return Location{
		Start: start,
		End:   end,
	}
}

func (l Location) Match(loc Location) bool {
	return l.Start <= loc.Start && loc.End <= l.End
}

type Blocks struct {
	content []byte
	regexes []*regexp.Regexp
	locs    []Location
	once    *sync.Once
}

func newBlocks(content []byte, regexes []*regexp.Regexp) Blocks {
	return Blocks{
		content: content,
		regexes: regexes,
		once:    new(sync.Once),
	}
}

func (b *Blocks) Match(block Location) bool {
	b.once.Do(b.find)
	for _, loc := range b.locs {
		if loc.Match(block) {
			return true
		}
	}
	return false
}

func (b *Blocks) find() {
	for _, regex := range b.regexes {
		results := regex.FindAllIndex(b.content, -1)
		if len(results) == 0 {
			continue
		}
		for _, r := range results {
			b.locs = append(b.locs, Location{
				Start: r[0],
				End:   r[1],
			})
		}
	}
}

func NewScanner(rulePath string, rules []Rule, allowRule AllowRule, excludeBlocks ExcludeBlock) Scanner { // TODO: remove rules, allowlist, excludeBlocks when rulePath implemented
	if rulePath != "" {
		// TODO: Load custom rules here
	}
	if len(rules) == 0 {
		rules = builtinRules
	}
	return Scanner{
		Rules:        rules, // TODO: Merge built-in rules and custom rules here
		AllowRule:    allowRule,
		ExcludeBlock: excludeBlocks,
	}
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

// Allow checks if the match is allowed
func (s Scanner) Allow(match string) bool {
	return s.AllowRule.Allow(match)
}

// AllowPath checks if the path is allowed
func (s Scanner) AllowPath(path string) bool {
	return s.AllowRule.AllowPath(path)
}

func (s Scanner) Scan(args ScanArgs) types.Secret {
	// Global allowed paths
	if s.AllowPath(args.FilePath) {
		return types.Secret{}
	}

	var findings []types.SecretFinding
	globalExcludedBlocks := newBlocks(args.Content, s.ExcludeBlock.Regexes)
	for _, rule := range s.Rules {
		// Check if the file path should be scanned by this rule
		if !rule.MatchPath(args.FilePath) {
			continue
		}

		// Check if the file path should be allowed
		if rule.AllowPath(args.FilePath) {
			continue
		}

		// Detect secrets
		indices := rule.Regex.FindAllIndex(args.Content, -1)
		if len(indices) == 0 {
			continue
		}

		localExcludedBlocks := newBlocks(args.Content, rule.ExcludeBlock.Regexes)
		for _, index := range indices {
			loc := newLocation(index[0], index[1])
			match := string(args.Content[loc.Start:loc.End])

			// Apply global and local allow rules.
			if s.Allow(match) || rule.Allow(match) {
				continue
			}

			// Skip the secret if it is within excluded blocks.
			if globalExcludedBlocks.Match(loc) || localExcludedBlocks.Match(loc) {
				continue
			}

			findings = append(findings, toFinding(rule, loc, args.Content))
		}
	}

	if len(findings) == 0 {
		return types.Secret{}
	}

	return types.Secret{
		FilePath: args.FilePath,
		Findings: findings,
	}
}

func toFinding(rule Rule, loc Location, content []byte) types.SecretFinding {
	startLine, endLine, matchLine := findLocation(loc.Start, loc.End, content)
	return types.SecretFinding{
		RuleID:    rule.ID,
		Type:      rule.Type,
		Severity:  rule.Severity,
		Title:     rule.Title,
		StartLine: startLine,
		EndLine:   endLine,
		Match:     matchLine,
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
