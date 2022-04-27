package pkg

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
)

func init() {
	analyzer.RegisterAnalyzer(&nodePkgLibraryAnalyzer{})
}

const (
	version      = 1
	requiredFile = "package.json"
)

type nodePkgLibraryAnalyzer struct{}

// Analyze analyzes package.json for node packages
func (a nodePkgLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.NodePkg, input.FilePath, input.Content, packagejson.NewParser())

	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", input.FilePath, err)
	}

	//Library path should be taken from input for this particular parser
	for _, app := range res.Applications {
		for i := range app.Libraries {
			app.Libraries[i].FilePath = input.FilePath
		}
	}

	return res, nil

}

func (a nodePkgLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return requiredFile == filepath.Base(filePath)
}

func (a nodePkgLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNodePkg
}

func (a nodePkgLibraryAnalyzer) Version() int {
	return version
}
