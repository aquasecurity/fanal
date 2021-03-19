package egg

import (
	"os"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/egg"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
)

func init() {
	analyzer.RegisterAnalyzer(&eggLibraryAnalyzer{})
}

var requiredFiles = []string{".egg-info", ".egg-info/PKG-INFO"}

type eggLibraryAnalyzer struct{}

func (a eggLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Egg, target.FilePath, target.Content, egg.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse METADATA: %w", err)
	}
	return res, nil
}

func (a eggLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, req := range requiredFiles {
		if strings.HasSuffix(filePath, req) {
			return true
		}
	}
	return false
}

func (a eggLibraryAnalyzer) Name() string {
	return library.Egg
}
