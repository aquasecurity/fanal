package poetry

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/poetry"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&poetryLibraryAnalyzer{})
}

var requiredFiles = []string{"poetry.lock"}

type poetryLibraryAnalyzer struct{}

func (a poetryLibraryAnalyzer) Analyze(filePath string, content []byte) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Poetry, filePath, content, poetry.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse poetry.lock: %w", err)
	}
	return res, nil
}

func (a poetryLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}
