package mod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/golang/mod"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&gomodAnalyzer{})
}

const version = 1

var requiredFiles = []string{"go.sum"}

type gomodAnalyzer struct{}

func (a gomodAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.GoMod, input.FilePath, input.Content, mod.Parse)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze %s: %w", input.FilePath, err)
	}
	return res, nil
}

func (a gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a gomodAnalyzer) Version() int {
	return version
}
