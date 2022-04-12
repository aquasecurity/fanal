package mod

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/golang/mod"
	"github.com/aquasecurity/go-dep-parser/pkg/golang/sum"
)

func init() {
	analyzer.RegisterAnalyzer(&gomodAnalyzer{})
}

const (
	version = 2
	GoMod   = "go.mod"
	GoSum   = "go.sum"
)

var requiredFiles = []string{GoMod, GoSum}

type gomodAnalyzer struct{}

func (a gomodAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var parser language.Parser
	switch filepath.Base(input.FilePath) {
	case GoMod:
		parser = mod.Parse
	case GoSum:
		parser = sum.Parse
	default:
		return nil, nil
	}

	res, err := language.Analyze(types.GoMod, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("failed to analyze %s: %w", input.FilePath, err)
	}
	return res, nil
}

func (a gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a gomodAnalyzer) Version() int {
	return version
}
