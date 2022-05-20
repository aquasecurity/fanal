package deps

import (
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/dotnet/core_deps"
)

func init() {
	analyzer.RegisterAnalyzer(&depsLibraryAnalyzer{})
}

const (
	version        = 1
	deps_extension = ".deps.json"
)

type depsLibraryAnalyzer struct{}

func (a depsLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Set the default parser
	parser := core_deps.NewParser()

	res, err := language.Analyze(types.DotNetCore, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf(".Net Core dependencies analysis error: %w", err)
	}

	return res, nil
}

func (a depsLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, deps_extension)
}

func (a depsLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDotNetDeps
}

func (a depsLibraryAnalyzer) Version() int {
	return version
}
