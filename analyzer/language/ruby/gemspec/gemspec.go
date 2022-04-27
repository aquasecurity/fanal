package gemspec

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/ruby/gemspec"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&gemspecLibraryAnalyzer{})
}

const version = 1

var fileRegex = regexp.MustCompile(`.*/specifications/.+\.gemspec`)

type gemspecLibraryAnalyzer struct{}

func (a gemspecLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.GemSpec, input.FilePath, input.Content, gemspec.NewParser())

	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", input.FilePath, err)
	}

	//Library path should be taken from input for this particular parser
	for _, app := range res.Applications {
		for i := range app.Libraries {
			app.Libraries[i].FilePath = input.FilePath
		}
	}

	return res, nil

}

func (a gemspecLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return fileRegex.MatchString(filepath.ToSlash(filePath))
}

func (a gemspecLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGemSpec
}

func (a gemspecLibraryAnalyzer) Version() int {
	return version
}
