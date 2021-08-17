package gemspec

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/ruby/gemspec"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func init() {
	analyzer.RegisterAnalyzer(&gemspecLibraryAnalyzer{})
}

const version = 1

var fileregex = regexp.MustCompile(`.*/specifications/.+.gemspec`)

type gemspecLibraryAnalyzer struct{}

func (a gemspecLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	r := bytes.NewReader(target.Content)
	parsedLib, err := gemspec.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", target.FilePath, err)
	}

	if parsedLib.Name == "" {
		return nil, nil
	}
	return language.ToAnalysisResult(types.GemSpec, target.FilePath, []godeptypes.Library{parsedLib}), nil
}

func (a gemspecLibraryAnalyzer) Required(filePath string, info os.FileInfo) bool {
	return fileregex.MatchString(filepath.ToSlash(filePath))
}

func (a gemspecLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGemSpec
}

func (a gemspecLibraryAnalyzer) Version() int {
	return version
}
