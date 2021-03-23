package json

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/open-policy-agent/conftest/parser/json"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/scanner"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".json"}

type ConfigScanner struct {
	parser *json.Parser
	scanner.Scanner
}

func NewConfigScanner(filePattern *regexp.Regexp, policyPaths, dataPaths []string) ConfigScanner {
	return ConfigScanner{
		parser:  &json.Parser{},
		Scanner: scanner.NewScanner(filePattern, policyPaths, dataPaths),
	}
}

func (s ConfigScanner) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := s.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse JSON (%s): %w", target.FilePath, err)
	}

	configType, err := s.DetectType(context.TODO(), parsed)
	if err != nil {
		return nil, err
	}
	if configType == "" {
		configType = types.JSON
	}

	results, err := s.ScanConfig(configType, target.FilePath, parsed)
	if err != nil {
		return nil, xerrors.Errorf("unable to scan JSON (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{Misconfigurations: results}, nil
}

func (s ConfigScanner) Required(filePath string, _ os.FileInfo) bool {
	if s.Match(filePath) {
		return true
	}

	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (s ConfigScanner) Type() analyzer.Type {
	return analyzer.TypeJSON
}

func (s ConfigScanner) Version() int {
	return version
}
