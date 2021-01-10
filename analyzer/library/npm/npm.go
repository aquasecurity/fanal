package npm

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/npm"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&npmLibraryAnalyzer{})
}

var requiredFiles = []string{"package-lock.json"}

type npmLibraryAnalyzer struct{}

func (a npmLibraryAnalyzer) Analyze(filePath string, content []byte) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Npm, filePath, content, npm.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse package-lock.json: %w", err)
	}
	return res, nil
}

func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}
