package gemspec

import (
	"bytes"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/gemspec"
)

func init() {
	analyzer.RegisterAnalyzer(&gemspecLibraryAnalyzer{})
}

const version = 1

type gemspecLibraryAnalyzer struct{}

func (a gemspecLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	r := bytes.NewReader(target.Content)
	parsedLibs, err := gemspec.Parse(r, target.FilePath)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", target.FilePath, err)
	}

	if len(parsedLibs) == 0 {
		return nil, nil
	}
	return library.ToAnalysisResult(types.GemSpec, target.FilePath, parsedLibs), nil
}

func (a gemspecLibraryAnalyzer) Required(filePath string, info os.FileInfo) bool {
	return strings.HasSuffix(filePath, ".gemspec")
}

func (a gemspecLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGemSpec
}

func (a gemspecLibraryAnalyzer) Version() int {
	return version
}
