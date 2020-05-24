package bundler

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/bundler"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&bundlerLibraryAnalyzer{})
}

var (
	requiredFiles = []string{"Gemfile.lock"}
)

type bundlerLibraryAnalyzer struct{}

func (a bundlerLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	r := bytes.NewBuffer(content)
	libs, err := bundler.Parse(r)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with Gemfile.lock: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Libraries: libs,
	}, nil
}

func (a bundlerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a bundlerLibraryAnalyzer) Name() string {
	return library.Bundler
}
