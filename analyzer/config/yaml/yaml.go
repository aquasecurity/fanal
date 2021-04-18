package yaml

import (
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/config/parser/yaml"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".yaml", ".yml"}

type ConfigAnalyzer struct {
	parser      *yaml.Parser
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		parser:      &yaml.Parser{},
		filePattern: filePattern,
	}
}

func (s ConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	// YAML might have sub documents separated by "---"
	//
	// If the current configuration contains multiple configurations, evaluate each policy
	// independent from one another and aggregate the results under the same file name.
	docs := s.parser.SeparateSubDocuments(target.Content)

	var configs []types.Config
	for _, doc := range docs {
		parsed, err := s.parser.Parse(doc)
		if err != nil {
			return nil, xerrors.Errorf("unable to parse YAML (%s): %w", target.FilePath, err)
		}

		configs = append(configs, types.Config{
			Type:     types.YAML,
			FilePath: target.FilePath,
			Content:  parsed,
		})
	}

	return &analyzer.AnalysisResult{
		Configs: configs,
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
	return analyzer.TypeYaml
}

func (s ConfigAnalyzer) Version() int {
	return version
}
