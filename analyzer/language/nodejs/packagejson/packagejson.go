package packagejson

import (
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
)

func init() {
	analyzer.RegisterAnalyzer(&pkgJsonLibraryAnalyzer{})
}

const version = 1

const requiredFile = "package.json"

type pkgJsonLibraryAnalyzer struct{}

func (a pkgJsonLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsedLib, err := packagejson.Parse(bytes.NewReader(target.Content))
	if err != nil {
		return nil, xerrors.Errorf("unable to parse package-lock.json: %w", err)
	}
	return &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.PkgJson,
				FilePath: target.FilePath,
				Libraries: []types.LibraryInfo{
					{
						FilePath: target.FilePath,
						Library:  parsedLib,
					},
				},
			},
		},
	}, nil
}

func (a pkgJsonLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return requiredFile == fileName
}

func (a pkgJsonLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePkgjson
}

func (a pkgJsonLibraryAnalyzer) Version() int {
	return version
}
