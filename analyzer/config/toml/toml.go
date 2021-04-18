package toml

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/open-policy-agent/conftest/parser/toml"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".toml"}

type ConfigAnalyzer struct {
	parser      *toml.Parser
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		parser:      &toml.Parser{},
		filePattern: filePattern,
	}
}

func (s ConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := s.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse TOML (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.TOML,
				FilePath: target.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

func (s ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if s.filePattern != nil && s.filePattern.MatchString(filePath) {
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

func (s ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTOML
}

func (s ConfigAnalyzer) Version() int {
	return version
}
