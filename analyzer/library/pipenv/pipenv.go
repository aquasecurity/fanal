package pipenv

import (
	"bytes"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&pipenvLibraryAnalyzer{})
}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]types.LibraryInfo, error) {
	libMap := map[types.FilePath][]types.LibraryInfo{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := pipenv.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		for _, lib := range libs {
			libMap[types.FilePath(filename)] = append(libMap[types.FilePath(filename)], types.LibraryInfo{
				Library: lib,
			})
		}
	}
	return libMap, nil
}

func (a pipenvLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Pipfile.lock"}
}

func (a pipenvLibraryAnalyzer) Name() string {
	return library.Pipenv
}
