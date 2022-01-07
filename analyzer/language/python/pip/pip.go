package pip

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/python/pip"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&pipLibraryAnalyzer{})
}

const version = 1

var requiredFile = "requirements.txt"

type pipLibraryAnalyzer struct{}

func (a pipLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Pip, input.FilePath, input.Content, pip.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse requirements.txt: %w", err)
	}
	return res, nil
}

func (a pipLibraryAnalyzer) Required(dir string, filePath string, osInfo os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	if fileName == requiredFile {
		return true
	}

	// Test for .txt/.in file combinations, which indicate pip-compile files.
	if dir != "" && strings.HasSuffix(fileName, ".txt") {
		// Create new filepath that has the same path but ends with .in
		inFilePath := strings.TrimSuffix(filePath, ".txt") + ".in"

		// Check whether in file exists.
		if _, err := os.Stat(path.Join(dir, inFilePath)); err == nil {
			return true
		}
	}

	return false
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}
