package pipenv

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&pipenvLibraryAnalyzer{})
}

var requiredFiles = []string{"Pipfile.lock"}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(filePath string, content []byte) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Pipenv, filePath, content, pipenv.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Pipfile.lock: %w", err)
	}
	return res, nil
}

func (a pipenvLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pipenvLibraryAnalyzer) Name() string {
	return library.Pipenv
}
