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

func NewConfigScanner(filePattern *regexp.Regexp, namespaces, policyPaths, dataPaths []string) (ConfigScanner, error) {
	s, err := scanner.New(filePattern, namespaces, policyPaths, dataPaths)
	if err != nil {
		return ConfigScanner{}, xerrors.Errorf("unable to initialize config scanner: %w", err)
	}

	return ConfigScanner{
		parser:  &docker.Parser{},
		Scanner: s,
	}, nil
}

func (s ConfigScanner) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := s.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse Dockerfile (%s): %w", target.FilePath, err)
	}

	result, err := s.ScanConfig(types.Dockerfile, target.FilePath, parsed)
	if err != nil {
		return nil, xerrors.Errorf("unable to scan Dockerfile (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Misconfigurations: []types.Misconfiguration{result},
	}, nil
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
