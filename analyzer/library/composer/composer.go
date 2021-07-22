package composer

import (
	"bytes"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/composer"
	godepTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func init() {
	analyzer.RegisterAnalyzer(&composerLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"/composer.lock", "/wp-includes/version.php"}

type composerLibraryAnalyzer struct{}

func (a composerLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsedLibs := []godepTypes.Library{}
	var err error
	r := bytes.NewReader(target.Content)
	if strings.HasSuffix(target.FilePath, "/composer.lock") {
		parsedLibs, err = composer.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse %s: %w", target.FilePath, err)
		}
	} else if strings.HasSuffix(target.FilePath, "/wp-includes/version.php") {
		parsedLibs, err = composer.ParseWordPress(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse %s: %w", target.FilePath, err)
		}
	}
	if len(parsedLibs) == 0 {
		return nil, nil
	}
	return library.ToAnalysisResult(types.Composer, target.FilePath, parsedLibs), nil
}

func (a composerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, filename := range requiredFiles {
		if strings.HasSuffix(filePath, filename) {
			return true
		}
	}
	return false
}

func (a composerLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposer
}

func (a composerLibraryAnalyzer) Version() int {
	return version
}
