package packaging

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
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

	res, err := language.Analyze(types.PythonPkg, input.FilePath, input.Content, p)

	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", input.FilePath, err)
	}

	//Library path should be taken from input for this particular parser
	if res != nil {
		for _, app := range res.Applications {
			for i := range app.Libraries {
				app.Libraries[i].FilePath = input.FilePath
			}
		}
	}

	return res, nil

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
