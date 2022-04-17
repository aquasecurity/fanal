package secret

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/fanal/types"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	*global
}

type global struct {
	Rules        []Rule       `yaml:"rules"`
	AllowRule    AllowRule    `yaml:"allow-rule"`
	ExcludeBlock ExcludeBlock `yaml:"exclude-block"`
}

// Allow checks if the match is allowed
func (g global) Allow(match string) bool {
	return g.AllowRule.Allow(match)
}

// AllowPath checks if the path is allowed
func (g global) AllowPath(path string) bool {
	return g.AllowRule.AllowPath(path)
}

// Regexp adds unmarshalling from YAML for regexp.Regexp
type Regexp struct {
	*regexp.Regexp
}

func MustCompile(str string) *Regexp {
	return &Regexp{regexp.MustCompile(str)}
}

// UnmarshalYAML unmarshals YAML into a regexp.Regexp
func (r *Regexp) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	regex, err := regexp.Compile(v)
	if err != nil {
		return xerrors.Errorf("regexp compile error: %w", err)
	}

	r.Regexp = regex
	return nil
}

type Rule struct {
	ID              string                   `yaml:"id"`
	Category        types.SecretRuleCategory `yaml:"category"`
	Title           string                   `yaml:"title"`
	Severity        string                   `yaml:"severity"`
	Regex           *Regexp                  `yaml:"regex"`
	Keywords        []string                 `yaml:"keywords"`
	Path            *Regexp                  `yaml:"path"`
	AllowRule       AllowRule                `yaml:"allow-rule"`
	ExcludeBlock    ExcludeBlock             `yaml:"exclude-block"`
	SecretGroupName string                   `yaml:"secret-group-name"`
}

func (r *Rule) FindLocations(content []byte) []Location {
	if r.Regex == nil {
		return nil
	}
	var indices [][]int
	if r.SecretGroupName == "" {
		indices = r.Regex.FindAllIndex(content, -1)
	} else {
		indices = r.FindSubmatchIndices(content)
	}

	var locs []Location
	for _, index := range indices {
		locs = append(locs, Location{
			Start: index[0],
			End:   index[1],
		})
	}
	return locs
}

func (r *Rule) FindSubmatchIndices(content []byte) [][]int {
	var indices [][]int
	matchsLocs := r.Regex.FindAllSubmatchIndex(content, -1)
	for _, matchLocs := range matchsLocs {
		for i, name := range r.Regex.SubexpNames() {
			if name == r.SecretGroupName {
				startLocIndex := 2 * i
				endLocIndex := startLocIndex + 1
				indices = append(indices, []int{matchLocs[startLocIndex], matchLocs[endLocIndex]})
			}
		}
	}
	return indices
}

func (r *Rule) MatchPath(path string) bool {
	if r.Path == nil {
		return true
	}
	return matchString(path, r.Path)
}

func (r *Rule) MatchKeywords(content []byte) bool {
	if r.Keywords == nil || len(r.Keywords) == 0 {
		return true
	}

	for _, kw := range r.Keywords {
		if bytes.Contains(bytes.ToLower(content), []byte(strings.ToLower(kw))) {
			return true
		}
	}

	return false
}

func (r *Rule) AllowPath(path string) bool {
	return r.AllowRule.AllowPath(path)
}

func (r *Rule) Allow(match string) bool {
	return r.AllowRule.Allow(match)
}

type AllowRule struct {
	Description string    `yaml:"description"`
	Regexes     []*Regexp `yaml:"regexes"`
	Paths       []*Regexp `yaml:"paths"`
}

func (a AllowRule) AllowPath(path string) bool {
	return matchString(path, a.Paths...)
}

func (a AllowRule) Allow(match string) bool {
	return matchString(match, a.Regexes...)
}

func matchString(s string, regexps ...*Regexp) bool {
	for _, r := range regexps {
		if r != nil && r.MatchString(s) {
			return true
		}
	}
	return false
}

type ExcludeBlock struct {
	Description string    `yaml:"description"`
	Regexes     []*Regexp `yaml:"regexes"`
}

type Location struct {
	Start int
	End   int
}

func (l Location) Match(loc Location) bool {
	return l.Start <= loc.Start && loc.End <= l.End
}

type Blocks struct {
	content []byte
	regexes []*Regexp
	locs    []Location
	once    *sync.Once
}

func newBlocks(content []byte, regexes []*Regexp) Blocks {
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

func NewScanner(configPath string) (Scanner, error) {
	var config global
	if configPath == "" {
		config.Rules = builtinRules
		config.AllowRule = builtinGlobalAllowRule
	} else {
		f, err := os.Open(configPath)
		if err != nil {
			return Scanner{}, xerrors.Errorf("file open error %s: %w", configPath, err)
		}
		defer f.Close()

		if err = yaml.NewDecoder(f).Decode(&config); err != nil {
			return Scanner{}, xerrors.Errorf("secrets config decode error: %w", err)
		}
		// TODO: add merge allow rules
		config.Rules = mergeRules(config.Rules, builtinRules)
	}
	return Scanner{global: &config}, nil
}

func mergeRules(custom, builtin []Rule) []Rule {
	custom = append(custom, builtin...)
	slices.SortStableFunc(custom, func(a, b Rule) bool {
		return a.ID < b.ID
	})

	// Unique rules by ID and prefer custom rules.
	slices.CompactFunc(custom, func(a, b Rule) bool {
		return a.ID == b.ID
	})
	return custom
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func (s Scanner) Scan(args ScanArgs) types.Secret {
	// Global allowed paths
	if s.AllowPath(args.FilePath) {
		return types.Secret{
			FilePath: args.FilePath,
		}
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

		// Check if the file content contains keywords and should be scanned
		if !rule.MatchKeywords(args.Content) {
			continue
		}

		// Detect secrets
		locs := rule.FindLocations(args.Content)
		if len(locs) == 0 {
			continue
		}

		localExcludedBlocks := newBlocks(args.Content, rule.ExcludeBlock.Regexes)
		for _, loc := range locs {
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
		Category:  rule.Category,
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
	matchLine = strings.TrimSpace(strings.ReplaceAll(matchLine, match, "*****"))

	return startLineNum, endLineNum, matchLine
}
