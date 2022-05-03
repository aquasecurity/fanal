package packaging

import (
	"context"
	"github.com/aquasecurity/fanal/types"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/go-dep-parser/pkg/python/packaging"
)

func init() {
	analyzer.RegisterAnalyzer(&packagingAnalyzer{})
}

const version = 1

var (
	requiredFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg", // zip format
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",

		// wheel
		".dist-info/METADATA",
	}
)

type packagingAnalyzer struct{}

// Analyze analyzes egg and wheel files.
func (a packagingAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := packaging.NewParser(input.FilePath, input.Info.Size(), a.Required)
	libs, deps, err := p.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}

	return language.ToAnalysisResult(types.PythonPkg, input.FilePath, input.FilePath, libs, deps), nil
}

func (a packagingAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// For Windows
	filePath = filepath.ToSlash(filePath)

	for _, r := range requiredFiles {
		if strings.HasSuffix(filePath, r) {
			return true
		}
	}
	return false
}

func (a packagingAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkg
}

func (a packagingAnalyzer) Version() int {
	return version
}
