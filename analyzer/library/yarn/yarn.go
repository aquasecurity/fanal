package yarn

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/go-dep-parser/pkg/yarn"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&yarnLibraryAnalyzer{})
}

var requiredFiles = []string{"yarn.lock"}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	r := bytes.NewBuffer(content)
	libs, err := yarn.Parse(r)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with yarn.lock: %w", err)
	}

	return analyzer.AnalyzeReturn{
		Libraries: libs,
	}, nil
}

func (a yarnLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a yarnLibraryAnalyzer) Name() string {
	return library.Yarn
}
