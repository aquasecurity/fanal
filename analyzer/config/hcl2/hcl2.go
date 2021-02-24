package hcl2

import (
	"os"
	"path/filepath"

	"github.com/open-policy-agent/conftest/parser/hcl2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&hcl2ConfigAnalyzer{
		parser: &hcl2.Parser{},
	})
}

const version = 2

var requiredExts = []string{".hcl"}

type hcl2ConfigAnalyzer struct {
	parser *hcl2.Parser
}

func (a hcl2ConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse HCL2 (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.HCL2,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

func (a hcl2ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (a hcl2ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHCL2
}

func (a hcl2ConfigAnalyzer) Version() int {
	return version
}
