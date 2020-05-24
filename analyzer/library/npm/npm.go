package npm

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/npm"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&npmLibraryAnalyzer{})
}

var requiredFiles = []string{"package-lock.json"}

type npmLibraryAnalyzer struct{}

func (a npmLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	r := bytes.NewBuffer(content)
	libs, err := npm.Parse(r)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with Cargo.lock: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Libraries: libs,
	}, nil
}

func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a npmLibraryAnalyzer) Name() string {
	return library.Npm
}
