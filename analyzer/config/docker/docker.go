package docker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/conftest/parser/docker"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/scanner"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredFile = "Dockerfile"

type ConfigScanner struct {
	parser *docker.Parser
	scanner.Scanner
}

func NewConfigScanner(filePattern *regexp.Regexp, policyPaths, dataPaths []string) ConfigScanner {
	return ConfigScanner{
		parser:  &docker.Parser{},
		Scanner: scanner.NewScanner(filePattern, policyPaths, dataPaths),
	}
}

func (s ConfigScanner) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := s.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse Dockerfile (%s): %w", target.FilePath, err)
	}

	results, err := s.ScanConfig(types.Dockerfile, target.FilePath, parsed)
	if err != nil {
		return nil, xerrors.Errorf("unable to scan Dockerfile (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{Misconfigurations: results}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFile
func (s ConfigScanner) Required(filePath string, _ os.FileInfo) bool {
	if s.Match(filePath) {
		return true
	}

	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	if strings.EqualFold(base, requiredFile+ext) {
		return true
	}
	if strings.EqualFold(ext, "."+requiredFile) {
		return true
	}

	return false
}

func (s ConfigScanner) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (s ConfigScanner) Version() int {
	return version
}
