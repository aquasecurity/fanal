package composer

import (
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/composer"
)

func init() {
	analyzer.RegisterAnalyzer(&composerLibraryAnalyzer{})
}

var (
	requiredFiles = []string{"composer.lock"}
)

type composerLibraryAnalyzer struct{}

func (a composerLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	r := bytes.NewBuffer(content)
	libs, err := composer.Parse(r)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with composer.lock: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Libraries: libs,
	}, nil
}

func (a composerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a composerLibraryAnalyzer) Name() string {
	return library.Composer
}
