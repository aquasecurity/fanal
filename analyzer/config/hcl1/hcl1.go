package hcl1

import (
	"os"
	"path/filepath"

	"github.com/open-policy-agent/conftest/parser/hcl1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&hcl1ConfigAnalyzer{
		parser: &hcl1.Parser{},
	})
}

const version = 1

var requiredExts = []string{".hcl"}

type hcl1ConfigAnalyzer struct {
	parser *hcl1.Parser
}

func (a hcl1ConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse HCL1 (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.HCL1,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

func (a hcl1ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (a hcl1ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHCL1
}

func (a hcl1ConfigAnalyzer) Version() int {
	return version
}
