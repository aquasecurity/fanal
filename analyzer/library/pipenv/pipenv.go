package pipenv

import (
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"
)

func init() {
	analyzer.RegisterAnalyzer(&pipenvLibraryAnalyzer{})
}

var requiredFiles = []string{"Pipfile.lock"}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	r := bytes.NewBuffer(content)
	libs, err := pipenv.Parse(r)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with Pipfile.lock: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Libraries: libs,
	}, nil
}

func (a pipenvLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pipenvLibraryAnalyzer) Name() string {
	return library.Pipenv
}
